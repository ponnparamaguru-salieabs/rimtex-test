from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required,  user_passes_test
from django.contrib.auth.hashers import make_password
from django.contrib.auth import login as auth_login, authenticate
from django.contrib import messages
from django.contrib.auth.models import User
from django.db.models import Q
from django.core.serializers import serialize
from django.http import JsonResponse, HttpResponseForbidden
from django.core.files.storage import default_storage
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from .forms import UserForm, MillLayoutForm
from .models import UserProfile, Machine, Mill, MillMachine, MillInfo, MillShift, MillLayout, MillLine, SetupMachine, MachineType, MachineSetting, MachineOverride, MachineConnectionLog, MachineStoppage
from .decorators import role_required, permission_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from datetime import datetime
import json
import uuid
import paho.mqtt.client as mqtt
import logging
import threading
import os
from django.conf import settings

# from collections import defaultdict
# import json

# device_aging = defaultdict(lambda: defaultdict(int)) 

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

mqtt_broker = "104.251.222.237"
mqtt_port = 1883
mqtt_client = mqtt.Client(client_id="unique_client_id", clean_session=False)
received_data = {}

device_type_map = {
    'POC': 'Carding',  
    'POB': 'Breaker',  
    'PIB': 'Breaker',  
    'PIK': 'Comber',   
    'POK': 'Comber',   
    'POF': 'Finisher', 
    'PIF': 'Finisher', 
    'POU': 'Unilap',   
    'PIU': 'Unilap',   
    'POR': 'Roving',   
    'PIR': 'Roving'
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
connection_established = False

def on_connect(client, userdata, flags, rc):
    global connection_established
    if rc == 0:
        if not connection_established:
            logger.info("Connected to MQTT broker successfully")
            print("Connected to MQTT broker successfully")
            connection_established = True
        if userdata is None:
            userdata = {}
        if 'subscribed_topics' not in userdata:
            userdata['subscribed_topics'] = []
        for device_id in userdata.get('device_ids', []):
            topic = f"{device_id}_OUT"
            if topic not in userdata['subscribed_topics']:
                mqtt_client.subscribe(topic)
                userdata['subscribed_topics'].append(topic)
                logger.info(f"Subscribed to {topic}")
                print(f"Subscribed to {topic}")
    else:
        logger.error(f"Failed to connect with result code {rc}")
        print(f"Failed to connect with result code {rc}")
        mqtt_client.reconnect()

def on_message(client, userdata, msg):
    topic = msg.topic
    if topic not in userdata['subscribed_topics']:
        logger.info(f"Received message on topic {topic} but not subscribed to this topic. Ignoring message.")
        return

    message = msg.payload.decode()
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

def find_machine(device_id):
    device_prefix = device_id[:3]
    return device_type_map.get(device_prefix, 'Unknown')
    
def process_received_data(data, topic, userdata):
    request = userdata.get('request', None)
    if request is None:
        logger.warning(f"'request' not found in userdata. Skipping processing for topic {topic}")
        return
    device_id = data.get('deviceID')
    can_id = data.get('canID')
    position_id = data.get('positionID')
    can_result = data.get('canResult')
    timestamp = data.get('timestamp')
    if not all([device_id, can_id, position_id]):
        logger.warning(f"Missing essential data in message: {data}")
        return
    associated_lines, mill_id = find_device_line(device_id, request)
    logger.info(f"Processing received data: deviceID={device_id}, canID={can_id}, positionID={position_id}, CanResult={can_result}")

    if can_result == 'override':
        device_type_prefix = device_id[:3]
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
    if device_id.startswith('PO'):
        received_data[can_id] = {
            'positionID': position_id
        }
        logger.info(f"Stored received data for can_id {can_id}: {received_data[can_id]}")
        connection_log, created = MachineConnectionLog.objects.update_or_create(
            can_id=can_id,
            defaults={
                'line_id': associated_lines[0].id,
                'mill_id': mill_id,
                'output_machine': find_machine(device_id),
                'output_position': position_id,
                'output_time': timezone.make_aware(datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")),
                'input_machine': None,
                'input_position': None,
                'input_time': None
            }
        )
        if created:
            logger.info(f"Created new connection log for output device can_id {can_id} with output position {position_id}")
        else:
            logger.info(f"Updated connection log for output device can_id {can_id} with output position {position_id}")
    elif device_id.startswith('PI'):
        connection_log = MachineConnectionLog.objects.filter(can_id=can_id).first()
        print(connection_log)
        input_machine = find_machine(device_id)
        if connection_log:
            output_position = connection_log.output_position
            logger.info(f"Retrieved output position {output_position} from the database for can_id {can_id}. Validating...")
            print(f"Retrieved output position {output_position} from the database for can_id {can_id}. Validating...")
            if output_position in connection_rules and position_id in connection_rules[output_position]:
                connection_log.input_machine = input_machine
                connection_log.input_position = position_id
                connection_log.input_time = timezone.make_aware(datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S"))
                connection_log.save()
                reason = f"Position {position_id} is valid for output position {output_position}. Connection accepted."
                logger.info(f"Connection accepted for can_id {can_id} with input machine {device_id} and input position {position_id}. Reason: {reason}")
                publish_accept_message(device_id, can_id)
            else:
                reason = f"Position {position_id} does not match the valid positions for output position {output_position}. Connection rejected."
                logger.warning(f"Connection rejected for can_id {can_id}. Reason: {reason}")
                device_type_prefix = device_id[:3]
                device_type = device_type_map.get(device_type_prefix, 'Unknown')
                for line in associated_lines:
                    line_id = line.id
                    machine_stoppage, created = MachineStoppage.objects.get_or_create(
                        mill_id=mill_id,
                        line_id=line_id,
                        device_type=device_type,
                        defaults={'count': 0}
                    )
                    machine_stoppage.count += 1
                    machine_stoppage.save()
                    logger.info(f"Mill {mill_id} - {device_type} stoppage count in Line {line_id}: {machine_stoppage.count}")
                    print(f"Mill {mill_id} - {device_type} stoppage count in Line {line_id}: {machine_stoppage.count}")
                publish_reject_message(device_id, can_id)
        else:
            reason = f"No matching connection log found for can_id {can_id} with NULL input_machine."
            logger.warning(f"Connection rejected for can_id {can_id}. Reason: {reason}")

def publish_accept_message(device_id, can_id):
    topic = f"{device_id}_IN"
    message = json.dumps({
        'deviceId': device_id,
        'canID': can_id,
        'canResult': 'Accept'
    })
    mqtt_client.publish(topic, message)
    logger.info(f"Published accepted message to {topic}: {message}")
    print(f"Published accepted message to {topic}: {message}")

def publish_reject_message(device_id, can_id):
    topic = f"{device_id}_IN"
    message = json.dumps({
        'deviceId': device_id,
        'canID': can_id,
        'canResult': 'Reject'
    })
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
    userdata = {
        'device_ids': device_ids, 
        'request': request, 
        'subscribed_topics': [] 
    }
    mqtt_client.user_data_set(userdata)
    connect_mqtt()

def find_device_line(device_id, request):
    associated_lines = []
    file_path = os.path.join(settings.BASE_DIR, 'mill_line_data.json')
    
    try:
        with open(file_path, 'r') as json_file:
            data = json.load(json_file)
            mill_id = data.get('request', {}).get('mill_id') 
            if not mill_id:
                logger.error("Mill ID is missing in the JSON data")
                return [], []
    except FileNotFoundError:
        logger.error(f"File {file_path} not found.")
        return [], []
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON from {file_path}: {e}")
        return [], []
    except Exception as e:
        logger.error(f"Error loading mill_line_data.json: {e}")
        return [], []
    try:
        mill = Mill.objects.get(id=mill_id) 
    except Mill.DoesNotExist:
        logger.error(f"Mill with ID {mill_id} does not exist")
        return [], []
    
    logger.info(f"Mill ID: {mill.id}")
    started_lines = MillLine.objects.filter(mill=mill, is_start=True)

    for line in started_lines:
        layout_data = line.layout_data
        formatted_connections, device_ids = format_layout_data(layout_data)
        if device_id in device_ids:
            associated_lines.append(line)
    return associated_lines, mill_id

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
                    formatted_connection = f"PO{machine_prefix}{node_number}{output_name.split('_')[1].zfill(3)} -> PI{target_machine_prefix}{target_node_number}{target_output.split('_')[1].zfill(3)}"
                    formatted_connections.append(formatted_connection)
        if 'inputs' in node and node['inputs']:
            device_id = f"PI{machine_prefix}{node_number}" 
            device_ids.append(device_id)
        if 'outputs' in node and node['outputs']:
            device_id = f"PO{machine_prefix}{node_number}" 
            device_ids.append(device_id)
    return formatted_connections, device_ids


def load_mill_line_data():
    file_path = os.path.join(settings.BASE_DIR, 'mill_line_data.json')
    
    try:
        with open(file_path, 'r') as json_file:
            data = json.load(json_file)
            all_device_ids = data.get('all_device_ids', [])
            formatted_connections_for_lines = data.get('formatted_connections_for_lines', [])
            request_data = data.get("request", {})
            logger.info(f"Loaded data from {file_path}")
            return all_device_ids, formatted_connections_for_lines, request_data
    except FileNotFoundError:
        logger.error(f"File {file_path} not found.")
        return [], []
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON from {file_path}: {e}")
        return [], []
    except Exception as e:
        logger.error(f"Error loading mill_line_data.json: {e}")
        return [], []

all_device_ids, formatted_connections_for_lines, request_data = load_mill_line_data()
setup_mqtt(all_device_ids, formatted_connections_for_lines, request_data)