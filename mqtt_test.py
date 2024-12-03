logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

mqtt_broker = "104.251.222.237"
mqtt_port = 1883
mqtt_client = mqtt.Client(client_id="unique_client_id", clean_session=False)
received_data = {}

device_type_map = {
    'IB': 'Breaker',
    'IK': 'Comber',
    'IF': 'Finisher',
    'IU': 'Unilap',
    'IR': 'Roving'
}

override_count = {}

def parse_connection_rules(formatted_connections):
    connection_rules = {}
    for connection in formatted_connections:
        source, target = connection.split(" -> ")
        if source not in connection_rules:
            connection_rules[source] = []
        connection_rules[source].append(target)
    print(f"Parsed connection rules: {connection_rules}")
    logger.info(f"Parsed connection rules: {connection_rules}")
    
    return connection_rules

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("Connected to MQTT broker successfully")
        print("Connected to MQTT broker successfully")
        for device_id in userdata['device_ids']:
            mqtt_client.subscribe(f"{device_id}_OUT")
            logger.info(f"Subscribed to {device_id}_OUT")
            print(f"Subscribed to {device_id}_OUT")
    else:
        logger.error(f"Failed to connect with result code {rc}")
        print(f"Failed to connect with result code {rc}")

def on_message(client, userdata, msg):
    message = msg.payload.decode()  
    topic = msg.topic

    logger.info(f"Received message on topic {topic}: {message}")
    print(f"Received message on topic {topic}: {message}")

    try:
        data = json.loads(message)
        logger.info(f"Decoded JSON data: {data}")
        print(f"Decoded JSON data: {data}")
        process_received_data(data, topic, userdata)
    except json.JSONDecodeError:
        logger.error(f"Error decoding message from topic {topic}: {message}")
        print(f"Error decoding message from topic {topic}: {message}")

def process_received_data(data, topic, userdata):
    request = userdata.get('request', None)
    if request is None:
        logger.warning(f"'request' not found in userdata. Skipping processing for topic {topic}")
        return

    device_id = data.get('deviceId')
    can_id = data.get('canID')
    position_id = data.get('positionID')
    can_result = data.get('canResult')

    if not all([device_id, can_id, position_id]):
        logger.warning(f"Missing essential data in message: {data}")
        return

    associated_lines, mill_id = find_device_line(device_id, request)
    line_info = ", ".join([f"Line {line.id}" for line in associated_lines]) if associated_lines else "Unknown line"

    logger.info(f"Processing received data: deviceId={device_id}, canID={can_id}, positionID={position_id}, CanResult={can_result}, from {line_info} in Mill {mill_id}")
    print(f"Processing received data: deviceId={device_id}, canID={can_id}, positionID={position_id} from {line_info} in Mill {mill_id}")

    if can_result == 'override':
        device_type_prefix = device_id[:2]
        device_type = device_type_map.get(device_type_prefix, 'Unknown')  

        logger.info(f"Override detected for deviceId {device_id}, Device Type: {device_type}")

        for line in associated_lines:
            line_id = line.id

            machine_override, created = MachineOverride.objects.get_or_create(
                mill_id=mill_id,
                line_id=line_id,
                device_type=device_type,
                defaults={'count': 0}  
            )

            machine_override.count += 1
            machine_override.save()

            logger.info(f"Mill {mill_id} - {device_type} override count in Line {line_id}: {machine_override.count}")
            print(f"Mill {mill_id} - {device_type} override count in Line {line_id}: {machine_override.count}")

    if device_id.startswith('O'):
        received_data[can_id] = {'positionID': position_id, 'deviceId': device_id}
        logger.info(f"Stored or updated data for canID {can_id}: {received_data[can_id]}")
        print(f"Stored or updated data for canID {can_id}: {received_data[can_id]}")
        return

    elif device_id.startswith('I'):
        if can_id in received_data:
            stored_position_id = received_data[can_id]['positionID']
            logger.info(f"Stored positionID for canID {can_id}: {stored_position_id}")
            print(f"Stored positionID for canID {can_id}: {stored_position_id}")

            acceptance_reason, is_accepted = validate_position_id(position_id, stored_position_id)

            if is_accepted:
                logger.info(f"Accepted message for canID {can_id} and positionID {position_id}. Reason: {acceptance_reason}")
                print(f"Accepted message for canID {can_id} and positionID {position_id}. Reason: {acceptance_reason}")
                publish_accept_message(device_id)
            else:
                logger.warning(f"Rejected message for canID {can_id} and positionID {position_id}. Reason: {acceptance_reason}")
                print(f"Rejected message for canID {can_id} and positionID {position_id}. Reason: {acceptance_reason}")
                publish_reject_message(device_id)
        else:
            logger.warning(f"No stored data for canID {can_id}. Rejected message.")
            print(f"No stored data for canID {can_id}. Rejected message.")
            publish_reject_message(device_id)

def validate_position_id(position_id, stored_position_id):
    logger.info(f"Validating position {position_id} from stored position {stored_position_id}")
    if stored_position_id in connection_rules:
        expected_positions = connection_rules[stored_position_id]
        logger.info(f"Expected positions for {stored_position_id}: {expected_positions}")
        if position_id in expected_positions:
            logger.info(f"Position {position_id} is valid for transition from {stored_position_id}.")
            return f"Position {position_id} is valid. Transition allowed from {stored_position_id}.", True
    logger.warning(f"Position {position_id} is not valid for transition from {stored_position_id}.")
    return f"Position {position_id} is not valid for {stored_position_id}. Transition not allowed.", False

def publish_accept_message(device_id):
    topic = f"{device_id}_IN"
    message = json.dumps({'status': 'accepted'})
    mqtt_client.publish(topic, message)
    logger.info(f"Published accepted message to {topic}: {message}")
    print(f"Published accepted message to {topic}: {message}")

def publish_reject_message(device_id):
    topic = f"{device_id}_IN"
    message = json.dumps({'status': 'rejected'})
    mqtt_client.publish(topic, message)
    logger.info(f"Published rejected message to {topic}: {message}")
    print(f"Published rejected message to {topic}: {message}")

def start_mqtt_loop():
    mqtt_client.loop_start()

def connect_mqtt():
    try:
        mqtt_client.connect(mqtt_broker, mqtt_port, 60)
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message
        logger.info("Connecting to MQTT broker...")
        print("Connecting to MQTT broker...")
        start_mqtt_loop()
    except Exception as e:
        logger.error(f"Error connecting to MQTT broker: {e}")
        print(f"Error connecting to MQTT broker: {e}")

def setup_mqtt(device_ids, formatted_connections_for_lines, request):
    global connection_rules
    all_connections = [connection for sublist in formatted_connections_for_lines for connection in sublist]
    connection_rules = parse_connection_rules(all_connections)
    mqtt_client.user_data_set({'device_ids': device_ids, 'request': request})
    connect_mqtt()
    for device_id in device_ids:
        mqtt_client.subscribe(f"{device_id}_OUT")
        logger.info(f"Subscribed to {device_id}_OUT")
        print(f"Subscribed to {device_id}_OUT")

def millLine(request):
    user_profile = UserProfile.objects.get(user=request.user)
    mill = user_profile.mill
    lines = MillLine.objects.filter(mill=mill)
    started_lines = MillLine.objects.filter(mill=mill, is_start=True)

    all_device_ids = []
    formatted_connections_for_lines = []

    for line in started_lines:
        layout_data = line.layout_data
        formatted_connections, device_ids = format_layout_data(layout_data)
        formatted_connections_for_lines.append(formatted_connections)
        all_device_ids.extend(device_ids)

    all_device_ids = list(set(all_device_ids))

    for line in started_lines:
        layout_data = line.layout_data
        formatted_connections, _ = format_layout_data(layout_data)
        print(f"Formatted connections for line {line.id}: {formatted_connections}")

    print("All Device ID",all_device_ids)
    if all_device_ids and formatted_connections_for_lines:
        run_mqtt_script(formatted_connections_for_lines, all_device_ids)

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            line_id = data.get('line_id')
            stop = data.get('stop')
            start_date = data.get('start_date')
            end_date = data.get('end_date')
            logger.info(f"Received POST request to change line state: line_id={line_id}, stop={stop}, start_date={start_date}, end_date={end_date}")
            print(f"Received POST request to change line state: line_id={line_id}, stop={stop}, start_date={start_date}, end_date={end_date}")
            line = get_object_or_404(MillLine, id=line_id, mill=mill)

            if stop:
                line.is_start = False
                line.start_date = None
                line.end_date = None
                logger.info(f"Stopping line {line_id}")
                print(f"Stopping line {line_id}")
            else:
                line.start_date = start_date
                line.end_date = end_date
                line.is_start = True
                logger.info(f"Starting line {line_id} with start_date={start_date} and end_date={end_date}")
                print(f"Starting line {line_id} with start_date={start_date} and end_date={end_date}")
            line.save()

            return JsonResponse({'status': 'success'})
        except MillLine.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Line not found'})
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON data'})
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            print(f"Error handling POST request: {e}")
            return JsonResponse({'status': 'error', 'message': 'An error occurred'})

    return render(request, 'mill_line.html', {
        'breadcrumb': [
            {'name': 'Home', 'url': ''},
            {'name': 'Mill Line Configuration', 'url': ''},
        ],
        'active_menu': 'millLine',
        'lines': lines,
        'mill': mill,
        'formatted_connections_for_lines': formatted_connections_for_lines,
        'all_device_ids': all_device_ids,
    })

def find_device_line(device_id, request):
    associated_lines = []
    mill = UserProfile.objects.get(user=request.user).mill
    started_lines = MillLine.objects.filter(mill=mill, is_start=True)
    print(f"Mill ID: {mill.id}")

    for line in started_lines:
        layout_data = line.layout_data
        formatted_connections, device_ids = format_layout_data(layout_data)
        if device_id in device_ids:
            associated_lines.append(line)
    
    return associated_lines, mill.id  

def format_layout_data(layout_data):
    formatted_connections = []
    device_ids = []
    drawflow = layout_data.get('drawflow', {}).get('Home', {}).get('data', {})
    
    machine_type_mapping = {
        'carding': 'C1',
        'breaker': 'B1',
        'unilap': 'U1',
        'comber': 'K1',
        'finisher': 'F1',
        'roving': 'R1'
    }

    for node_id, node in drawflow.items():
        node_name = node.get('name')
        node_type = node_name.split()[0].lower() 
        node_number = node_name.split()[1]
        machine_prefix = machine_type_mapping.get(node_type, 'Unknown')

        for output_name, output in node.get('outputs', {}).items():
            if 'connections' in output and output['connections']:
                for connection in output['connections']:
                    target_node = connection['node']
                    target_output = connection['output']
                    target_node_data = drawflow.get(target_node, {})
                    target_node_name = target_node_data.get('name', '')
                    target_node_type = target_node_name.split()[0].lower() 
                    target_node_number = target_node_name.split()[1]
                    
                    target_machine_prefix = machine_type_mapping.get(target_node_type, 'Unknown')

                    formatted_connection = f"O{machine_prefix}{node_number}{output_name.split('_')[1].zfill(3)} -> I{target_machine_prefix}{target_node_number}{target_output.split('_')[1].zfill(3)}"
                    formatted_connections.append(formatted_connection)

        if 'inputs' in node and node['inputs']:
            device_id = f"I{machine_prefix}{node_number}"
            device_ids.append(device_id)
        if 'outputs' in node and node['outputs']:
            device_id = f"O{machine_prefix}{node_number}"
            device_ids.append(device_id)

    return formatted_connections, device_ids