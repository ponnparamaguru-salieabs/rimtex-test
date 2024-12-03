# Process received data
def process_received_data(data, topic, mill, line_id):    
    device_id = data.get('deviceId')
    can_id = data.get('canID')
    position_id = data.get('positionID')

    machine_type = None
    for prefix, machine in device_type_map.items():
        if device_id.startswith(prefix):
            machine_type = machine
            break

    if not machine_type:
        logger.warning(f"Unknown machine type for deviceId={device_id}")
        print(f"Unknown machine type for deviceId={device_id}")
        return  

    logger.info(f"Processing received data: deviceId={device_id}, canID={can_id}, positionID={position_id}")
    print(f"Processing received data: deviceId={device_id}, canID={can_id}, positionID={position_id}")

    if data.get('canResult') == 'override':
        # Increment override count for the specific mill and machine type
        if mill not in override_count_by_type[machine_type]:
            override_count_by_type[machine_type][mill] = 0
        override_count_by_type[machine_type][mill] += 1

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

    # Log total 'override' messages for this machine type and mill
    logger.info(f"Total 'override' messages for {machine_type} on mill {mill}: {override_count_by_type[machine_type].get(mill, 0)}")
    print(f"Total 'override' messages for {machine_type} on mill {mill}: {override_count_by_type[machine_type].get(mill, 0)}")


