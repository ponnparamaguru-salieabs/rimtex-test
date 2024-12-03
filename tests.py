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