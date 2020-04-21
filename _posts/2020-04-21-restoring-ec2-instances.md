---
layout: post
title: Automatically restoring EC2 instances
categories: [aws, cloud, pentest]
tags:
fullview: false
comments: true
---
I recently created a pentest lab in AWS for a course I am giving. In order to keep the structure easy to store and replicate I have published the [terraform files here](https://github.com/marcosValle/auto-pentest-lab). I should also publish the Ansible files one of these days.

One important feature in the lab was to automatically restore each box to its original state. After all, hackers do hack and the systems would be messed up sooner or later :). Therefore, we've decided each instance would be restored every 24h.

![Such a hacker!](https://github.com/marcosValle/marcosValle.github.io/tree/master/assets/media/instancereset/meme1.jpg)

The solution seemed simple enough. A scheduled lambda function would run a command to restore the instance state to a snapshot. Well, almost.

	DISCLAIMER: DO NOT USE THESE CODES IN PRODUCTION

# First Method - launch a new AMI

~~~
import boto3
from time import sleep

#connect
res = boto3.resource('ec2', aws_access_key_id='ACESS_KEY', aws_secret_access_key='SECRET_KEY', region_name='sa-east-1')

#delete existing instance
#filter by the instance name
filters = [{
            'Name': 'tag:Name',
            'Values': ['tst-reset']
        }]

print("Terminating instance")
instance = res.instances.filter(Filters=filters).terminate()
sleep(10) #wait for the instance to fully terminate

#create a new instance from AMI
tagSpecifications=[
    {
        'ResourceType': 'instance',
        'Tags': [
            {
                'Key': 'Name',
                'Value': 'tst-reset'
            },
        ]
    }
]

print("Creating new AMI image")
instance = res.create_instances(
        ImageId = 'ami-xxxxxxxxxxx', 
        InstanceType = 't2.micro',
        SecurityGroupIds = ['sg-xxxxxxxxxxxxxx',],
        SubnetId = 'subnet-xxxxxxxxxxxxxx',
        PrivateIpAddress = 'xxx.xxx.xxx.xxx',
        TagSpecifications = tagSpecifications,
        MinCount=1,
        MaxCount=1)
~~~

# Second Method - restore an EBS volume

~~~
import boto3
from time import sleep

instanceIds = ["i-xxxxxxxxxxxxxx"]
snapshotId = "snap-xxxxxxxxxxxxxxx"

def getAttachedVolumeId(instanceId):
    volumes = client.describe_volumes(
        Filters=[
            {
                'Name': 'attachment.instance-id',
                'Values': [
                    instanceId,
                ],
            }
        ])

    return volumes['Volumes'][0]['VolumeId']

def detachVolume(instanceId):
    try:
        attachedVolId = getAttachedVolumeId(instanceId)
        print("Attached volume ID {}".format(attachedVolId))
        print("Detaching volume {} from instance {}".format(attachedVolId, instanceIds[0]))
        sleep(10)
        client.detach_volume(InstanceId=instanceIds[0], VolumeId=attachedVolId)

        return attachedVolId
    except IndexError as e:
        print("No volume attached")

client = boto3.client('ec2', aws_access_key_id='AKIAJNAYRUYDQ4JRII6A', aws_secret_access_key='SECRET_KEY', region_name='sa-east-1')

print("Stopping Instance {}".format(instanceIds[0]))
client.stop_instances(InstanceIds=instanceIds)

print("Creating new volume from snapshot ID: {}".format(snapshotId))
restoredVol = client.create_volume(AvailabilityZone='sa-east-1a', SnapshotId=snapshotId)
restoredVolId = restoredVol["VolumeId"]
print("New volume restored {}".format(restoredVolId))

print("Getting the volume ID attached to {}".format(instanceIds[0]))
detachedVolId = detachVolume(instanceIds[0])

if detachedVolId:
    print("Deletting old volume from instance {}".format(instanceIds[0]))
    sleep(5)
    client.delete_volume(VolumeId=detachedVolId)

print("Attaching restored volume {}".format(restoredVolId))
sleep(10)
client.attach_volume(Device="/dev/sda1", InstanceId=instanceIds[0], VolumeId=restoredVolId)

print ("Starting instance")
client.start_instances(InstanceIds=instanceIds)
~~~

Now just run any of the options as a lambda function and schedule it by creating a CloudWatch event rule :)
