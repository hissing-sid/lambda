import boto3
import logging

ec2 = boto3.client('ec2')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns_topic_arn = 'arn:aws:sns:<region>:<account>:AWSAlerts'

def publish_message(sns_topic_arn, message, subject):
    sns_client = boto3.client('sns')
    
    try:
        response = sns_client.publish(TopicArn=sns_topic_arn,Message=message,Subject=subject)['MessageId']

    except ClientError:
        logger.exception(f'Could not publish message to the topic.')
        raise
    else:
        return response
        
def forensic_security_group(vpc_id):

    security_groups = ec2.describe_security_groups()
    forensic_group_ID = None

    # Check if we already have a SG available to us in this vpc
    for sg in security_groups['SecurityGroups']:
        if (sg['GroupName'] == 'Forensic Isolation') and (sg['VpcId'] == vpc_id):
            forensic_group_ID = sg['GroupId']

    # Check and create if necessary
    if forensic_group_ID is None:
        # We had better create it then
        response = ec2.create_security_group(GroupName='Forensic Isolation',
                                             Description='Forensic Isolation of instance doing nefarious things',
                                             VpcId=vpc_id,
                                             TagSpecifications=[
                                                 {
                                                     'ResourceType': 'security-group',
                                                     'Tags': [ { 'Key': 'Name',  'Value': 'Forensic Isolation'}]
                                                 },
                                             ],
        )
        forensic_group_ID =  response['GroupId']

    # Check whether the SG has any ingress or egress rules and remove them if they exist
    sg_rules_paginator = ec2.get_paginator('describe_security_group_rules')
    sg_rules_iterator = sg_rules_paginator.paginate(Filters=[{
                'Name': 'group-id',
                'Values': [forensic_group_ID]
            }])

    full_result = sg_rules_iterator.build_full_result()

    sg_rule_ingress_ids = []
    sg_rule_egress_ids = []
    for sg_rule in full_result['SecurityGroupRules']:
        if sg_rule['IsEgress']:
            sg_rule_egress_ids.append(sg_rule['SecurityGroupRuleId'])
        else:
            sg_rule_ingress_ids.append(sg_rule['SecurityGroupRuleId'])

    # Load up specific SG and remove any rules
    ec2r = boto3.resource('ec2')
    security_group = ec2r.SecurityGroup(forensic_group_ID)

    if sg_rule_ingress_ids:
        security_group.revoke_ingress(SecurityGroupRuleIds=sg_rule_ingress_ids)
    if sg_rule_egress_ids:
        security_group.revoke_egress(SecurityGroupRuleIds=sg_rule_egress_ids)

    # Done our work, now return the ID of the Forensic SG
    return forensic_group_ID

def isolate_instance(event):

    event_account= event["detail"]["accountId"]
    event_region= event["detail"]["region"]
    event_service = event["detail"]["service"]
    event_title = event["detail"]["title"]
    event_id = event["detail"]["id"]
    event_type = event["detail"]["type"]

    source_instance_Id = event["detail"]["resource"]["instanceDetails"]["instanceId"]
    source_network_interfaces = event["detail"]["resource"]["instanceDetails"]["networkInterfaces"]
    vpc_id = source_network_interfaces[0]["vpcId"]

    if event_service["action"]["networkConnectionAction"]["connectionDirection"] == 'OUTBOUND':
        # We have an internal instance doing stuff it shouldnt

        # Check whether instance still exists
        waiter = ec2.get_waiter('instance_exists')
        try:
            waiter.wait(InstanceIds=[source_instance_Id])
        except:
            logger.info(f'Instance: {source_instance_Id} no longer exists')
            return {"status": "failure", "message": 'Instance does not exist'}


        # ensure we have a forensic Security group available in this vpc
        fsg_id = forensic_security_group(vpc_id)

        # Replace security groups on the instance
        ec2.modify_instance_attribute(InstanceId=source_instance_Id, Groups=[fsg_id])
        logger.info(f'Attached forensic security group to instance: {source_instance_Id}')


        # shutdown the instance
        try:
            instance_state = ec2.describe_instance_status(InstanceIds=[instance_id])['InstanceStatuses'][0]['InstanceState']['Name']
            if instance_state == 'running':
                ec2.stop_instances(InstanceIds=[source_instance_Id])
                logger.info(f'Stopped instance: {source_instance_Id}')
        except:
            logger.info(f'Instance {source_instance_Id} not in running state.')
            
        # Notify security team of action taken

        subject = f'GuardDuty event: {event_title}'
        message = f"""
        Automated security response has triaged the following event.

        ------------------------------------------------------------------------------------
        Summary of the Event:
        ------------------------------------------------------------------------------------
        Account          :  {event_account}
        Region           :  {event_region}
        Event            :  {event_title}
        Event Type       :  {event_type}
        Source Instance  :  {source_instance_Id}
        ------------------------------------------------------------------------------------
        
        Actions Taken:
            - The instance {source_instance_Id} has had a isolation security group applied and shutdown awaiting your analysis.
        """

        logger.info(f'Emailing security team with update of actions taken.')
        message_id = publish_message(sns_topic_arn, message, subject)
        
    else:
        # must be an inbound attack if the source IP is outside of the vpc
        # Update NACL and notify
        x = 'x'
        

        
def lambda_handler(event, context):

    if event["source"] != "aws.guardduty":
        return {"status": "failure", "message": 'Incorrect invocation - exiting'}

    event_type = event["detail"]["type"]
    event_id = event["detail"]["id"]
    logger.info(f'Responding to GuardDuty event - {event_id}  {event_type}')

    # Triage the event and trigger correct response
    if  ( (event_type.find('SSHBruteForce')) or
          (event_type.find('CryptoCurrency')) or
          (event_type.find('PortSweep'))
        ):
        logger.info(f'Attempting to isolate offending instance')
        response = isolate_instance(event)
    else:
        response = 'Unhandled event - no action taken'

