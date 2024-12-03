import logging
import paho.mqtt.client as mqtt
import json
import sys

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

mqtt_broker = "104.251.222.237"
mqtt_port = 1883
mqtt_client = mqtt.Client(client_id="unique_client_id", clean_session=False)
received_data = {}
connection_rules = {}

device_type_map = {
    'IB': 'Breaker',
    'IK': 'Comber',
    'IF': 'Finisher',
    'IU': 'Unilap',
    'IR': 'Roving'
}
override_count = {
    'Breaker': 0,
    'Comber': 0,
    'Finisher': 0,
    'Unilap': 0,
    'Roving': 0
}

def parse_connection_rules(formatted_connections):
    connection_rules = {}
    for connection in formatted_connections:
        source, target = connection.split(" -> ")
        if source not in connection_rules:
            connection_rules[source] = []
        connection_rules[source].append(target)
    logger.info(f"Parsed connection rules: {connection_rules}")
    return connection_rules

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        if not userdata.get("connected_once", False):
            logger.info("Connected to MQTT broker successfully")
            userdata["connected_once"] = True

        if not userdata.get("subscribed", False):
            for device_id in userdata['device_ids']:
                mqtt_client.subscribe(f"{device_id}_OUT")
                logger.info(f"Subscribed to {device_id}_OUT")
            userdata["subscribed"] = True
            logger.info("Waiting for data...")
        else:
            if not userdata.get("logged_subscribed_message", False):
                logger.info("Already subscribed to topics, waiting for data.")
                userdata["logged_subscribed_message"] = True  
    else:
        logger.error(f"Failed to connect with result code {rc}")

def on_message(client, userdata, msg):
    message = msg.payload.decode()
    topic = msg.topic
    logger.info(f"Received message on topic {topic}: {message}")

    try:
        data = json.loads(message)
        logger.info(f"Decoded JSON data: {data}")
        process_received_data(data, topic)
    except json.JSONDecodeError:
        logger.error(f"Error decoding message from topic {topic}: {message}")

def process_received_data(data, topic):
    device_id = data.get('deviceId')
    can_id = data.get('canID')
    position_id = data.get('positionID')
    can_result = data.get('canResult')

    if not all([device_id, can_id, position_id]):
        logger.warning(f"Missing essential data in message: {data}")
        return
    logger.info(f"Processing received data: deviceId={device_id}, canID={can_id}, positionID={position_id}, canResult={can_result}")

    if can_result == 'override':
        device_type_prefix = device_id[:2]
        device_type = device_type_map.get(device_type_prefix, 'Unknown')

        logger.info(f"Override detected for deviceId {device_id}, Device Type: {device_type}")

        if device_type != 'Unknown':
            override_count[device_type] += 1
            logger.info(f"Override count for {device_type}: {override_count[device_type]}")

        if device_id.startswith('O'):
            received_data[can_id] = {'positionID': position_id, 'deviceId': device_id}
            logger.debug(f"Stored or updated data for canID {can_id}: {received_data[can_id]}")

    if device_id.startswith('O'):
        received_data[can_id] = {'positionID': position_id, 'deviceId': device_id}
        logger.info(f"Stored or updated data for canID {can_id}: {received_data[can_id]}")
        return

    elif device_id.startswith('I'):
        if can_id in received_data:
            stored_position_id = received_data[can_id]['positionID']
            logger.info(f"Stored positionID for canID {can_id}: {stored_position_id}")
            acceptance_reason, is_accepted = validate_position_id(position_id, stored_position_id)

            if is_accepted:
                logger.info(f"Accepted message for canID {can_id} and positionID {position_id}. Reason: {acceptance_reason}")
                publish_accept_message(device_id)
            else:
                logger.warning(f"Rejected message for canID {can_id} and positionID {position_id}. Reason: {acceptance_reason}")
                publish_reject_message(device_id)
        else:
            logger.warning(f"No stored data for canID {can_id}. Rejected message.")
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

def publish_reject_message(device_id):
    topic = f"{device_id}_IN"
    message = json.dumps({'status': 'rejected'})
    mqtt_client.publish(topic, message)
    logger.info(f"Published rejected message to {topic}: {message}")

def connect_mqtt():
    try:
        mqtt_client.connect(mqtt_broker, mqtt_port, 60)
        mqtt_client.on_connect = on_connect
        mqtt_client.on_message = on_message
        logger.info("Connecting to MQTT broker...")
    except Exception as e:
        logger.error(f"Error connecting to MQTT broker: {e}")
        return

def setup_mqtt(device_ids, formatted_connections_for_lines):
    global connection_rules

    # all_connections = [connection for sublist in formatted_connections_for_lines for connection in sublist]
    # connection_rules = parse_connection_rules(all_connections)

    connection_rules = parse_connection_rules([conn for sublist in formatted_connections_for_lines for conn in sublist])

    
    mqtt_client.user_data_set({'device_ids': device_ids})
    connect_mqtt()

    for device_id in device_ids:
        mqtt_client.subscribe(f"{device_id}_OUT")
        logger.info(f"Subscribed to {device_id}_OUT")

""" all_device_ids = ['OC1001', 'IB1002', 'OC1004']
formatted_connections_for_line_2 = ['OC1001001 -> IB1002007', 'OC1001002 -> IB1002001']
formatted_connections_for_line_3 = ['OC1004001 -> IB1001001', 'OC1004002 -> IB1001002', 'OC1004002 -> IB1001003', 'OB1001001 -> IB1003001']
formatted_connections_for_lines = [formatted_connections_for_line_2, formatted_connections_for_line_3] """


formatted_connections_for_lines = json.loads(sys.argv[1]) or ''
all_device_ids = json.loads(sys.argv[2]) or ''
setup_mqtt(all_device_ids, formatted_connections_for_lines)

mqtt_client.loop_forever()