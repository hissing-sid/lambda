import os, json, boto3

def lambda_handler(event, context):

  ec2 = boto3.client('ec2')
  response = ec2.describe_instances( Filters=[ { 'Name': 'instance-state-name', 'Values': ['running'] } ] )

  for r in response['Reservations']:
    for i in r['Instances']:
        instance = i['InstanceId']
        try:
            tag_list = json.dumps(i['Tags'])
            if 'keep-running' in tag_list: stop = 0
        except:
            stop = 1

        if stop:
            ec2.stop_instances(InstanceIds=[instance])
            print('Stopped instance: {}'.format(instance) )
            
    return {
        'statusCode': 200,
        'body': json.dumps('Autostop has run')
    }
