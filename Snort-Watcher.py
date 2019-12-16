#!/bin/python3
#Created by Milad Rezaei Cod.smr@gmail.com
import mysql.connector
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from os import path
import time

current_local_time = time.asctime(time.localtime(time.time()))  # generate script runtime


def alert_mail(m_message, m_sensor, m_subject):  # function for sending email
    # create message object instance
    msg = MIMEMultipart()

    message = m_message
    subject = m_subject
    sensor = m_sensor
    # setup the parameters of the message
    password = "password"
    msg['From'] = "src-email@domain.ir"
    msg['To'] = "destination-email@domain.ir"
    msg['Subject'] = "[Nids][{}][{}]".format(sensor, subject)

    # add in the message body
    msg.attach(MIMEText(message, 'plain'))

    # create server
    server = smtplib.SMTP('smtm_server_ip_address')

    server.starttls()

    # Login Credentials for sending the mail
    server.login(msg['From'], password)

    # send the message via the server.
    server.sendmail(msg['From'], msg['To'], msg.as_string())

    server.quit()

    print("successfully sent email to %s:" % (msg['To']))


# define list of class to monitor them
sig_class = [536, 544, 539, 541, 570, 566, 556, 568, 569, 561, 562, 547, 545, 540, 538, 537, 543, 549, 550, 551, 553,
             542, 559, 560, 565, 533, 558, 546, 549, 550, 551, 542, 554]
#define sensor name here to send them in email subject
sensor_sid = {'17': 'Shatel.ir', '18': 'Dns'}
# when script generate email address find class name in this dict
sig_class_name = {'544': 'attempted-admin', '539': 'attempted-dos', '536': 'attempted-recon', '541': 'attempted-user',
                  '535': 'bad-unknown', '570': 'client-side-exploit', '566': 'default-login-attempt',
                  '556': 'denial-of-service', '568': 'file-format', '563': 'icmp-event', '564': 'inappropriate-content',
                  '569': 'malware-cnc', '561': 'misc-activity', '562': 'misc-attack', '555': 'network-scan',
                  '557': 'non-standard-protocol', '533': 'not-suspicious', '565': 'policy-violation',
                  '558': 'protocol-command-decode', '546': 'rpc-portmap-decode', '567': 'sdf',
                  '547': 'shellcode-detect', '548': 'string-detect', '545': 'successful-admin', '540': 'successful-dos',
                  '538': 'successful-recon-largescale', '537': 'successful-recon-limited', '543': 'successful-user',
                  '549': 'suspicious-filename-detect', '550': 'suspicious-login', '551': 'system-call-detect',
                  '552': 'tcp-connection', '553': 'trojan-activity', '534': 'unknown', '542': 'unsuccessful-user',
                  '554': 'unusual-client-port-connection', '559': 'web-application-activity',
                  '560': 'web-application-attack'
                  }
"""
you can see a class name using by snort in this table and choose from them 
+--------------+--------------------------------+
| sig_class_id | sig_class_name                 |
+--------------+--------------------------------+
|          544 | attempted-admin                |
|          539 | attempted-dos                  |
|          536 | attempted-recon                |
|          541 | attempted-user                 |
|          535 | bad-unknown                    |
|          570 | client-side-exploit            |
|          566 | default-login-attempt          |
|          556 | denial-of-service              |
|          568 | file-format                    |
|          563 | icmp-event                     |
|          564 | inappropriate-content          |
|          569 | malware-cnc                    |
|          561 | misc-activity                  |
|          562 | misc-attack                    |
|          555 | network-scan                   |
|          557 | non-standard-protocol          |
|          533 | not-suspicious                 |
|          565 | policy-violation               |
|          558 | protocol-command-decode        |
|          546 | rpc-portmap-decode             |
|          567 | sdf                            |
|          547 | shellcode-detect               |
|          548 | string-detect                  |
|          545 | successful-admin               |
|          540 | successful-dos                 |
|          538 | successful-recon-largescale    |
|          537 | successful-recon-limited       |
|          543 | successful-user                |
|          549 | suspicious-filename-detect     |
|          550 | suspicious-login               |
|          551 | system-call-detect             |
|          552 | tcp-connection                 |
|          553 | trojan-activity                |
|          534 | unknown                        |
|          542 | unsuccessful-user              |
|          554 | unusual-client-port-connection |
|          559 | web-application-activity       |
|          560 | web-application-attack         |
+--------------+--------------------------------+
"""

# information for connecting to database
db_host = "localhost"
db_user = "root"
db_password = "password"
db_remote_database = "snort"

# connect to db
snort_db = mysql.connector.connect(
    host=db_host,
    user=db_user,
    passwd=db_password,
    database=db_remote_database
)

# open file which contain sum of event that script run last time
if not path.exists("total_old.txt"):
    total_old_file = snort_db.cursor()
    total_old_file.execute("select count(*) from acid_event ")
    for sum_data_old in total_old_file:
        total_old = open("total_old.txt", "w")
        total_old.write(str(sum_data_old))
        total_old.close()
        print("{}\ntotal_old.txt created please run script again ".format(current_local_time))
        total_old_file.close()
        exit()
else:
    read_old_total = open("total_old.txt", "r")
    old_total = str(read_old_total.read())
    print("{}\nold sum of event : %s".format(current_local_time) % old_total[1:-2])
    old_total = int(old_total[1:-2])
    read_old_total.close()

# sum of all events
snort_sum = snort_db.cursor()
snort_sum.execute("select count(*) from acid_event ")
for sum_data in snort_sum:
    total_old = open("total_old.txt", "w")
    total_old.write(str(sum_data))
    total_old.close()
    print("newest_row_number : %s " % sum_data)
    new_total = int(sum_data[0])
    snort_sum.close()

# check for alert
if int(old_total) == new_total:
    print("not new alert was found")
elif int(old_total) < new_total:
    diff = new_total - old_total  # different between last alert number and now
    print("%d new alert is found" % diff)

    snort_db_data = snort_db.cursor(dictionary=True)
    snort_db_data.execute(
        "select sid, cid, sig_name, sig_class_id,  timestamp, INET_NTOA(ip_src), INET_NTOA(ip_dst)   from acid_event "
        "order by timestamp DESC LIMIT %d" % diff)
    for data in snort_db_data:
        # print(data['sig_class_id'],data['sig_name'])
        if data['sig_class_id'] in sig_class:
            # print("sig_class-id : ", data['sig_class_id'])
            x_str = str(data['sig_class_id'])  # change int to str for use in dict and find name of class
            last_message = "#ID : {}  \n| Time : {} \n| Class : {} \n| Signature_name: {}    \n| Src_ip : {} \n| Dst_ip : {} \n \n #Generated by Snort-Watcher {}".format(data['cid'], data['timestamp'], sig_class_name[x_str], data['sig_name'], data['INET_NTOA(ip_src)'], data['INET_NTOA(ip_dst)'], current_local_time)
            sub = sig_class_name[x_str]  # sig_name sends in email subject
            sensor_db = str(data['sid'])
            for sens in sensor_sid:
                if sens == sensor_db:
                    last_sensor = sensor_sid[sens]
            alert_mail(last_message, last_sensor, sub)  # send alert
    snort_db_data.close()
elif int(old_total) > new_total:
    print("database probably changed")
    sh_command = 'find ~ -type f -name "total_old.txt" -exec rm  total_old.txt  {} /;'

snort_db.close()

# end __of__script
