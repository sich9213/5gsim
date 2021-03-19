#!/usr/bin/
# env python
"""sim_log.py"""

import sys

def Average(lst): 
    return round(sum(lst) / len(lst), 3)
    
# input comes from STDIN (standard input)
# for line in sys.stdin:
with open('output.log') as f:
# with open('output.log.210317-ogs-reg-10x6') as f:
    send_reg_list = []
    recv_id_req = []
    send_id_res = []        
    recv_auth_req = []
    send_auth_res = []
    amf_auth_time = []            
    recv_sec_mode = []
    send_sec_mode = []
    recv_context_setup_req = []
    send_context_setup_res = []
    send_context_setup_fail = []                
    send_reg_complete = []               
    recv_config_update_cmd = []
    send_dereg_req = []                
    recv_context_release_cmd = []
    send_context_release_complete = []                

    first_experiment = True
    ue_num = 0

    for line in f:
        line = line.strip()
        words = line.split("###")
        # print (words)
        # print (words[1:])
        ###
        if len(words) == 1:
            if words == ['']:
                continue
            if words[0] == 'PERFORMANCE MEASUREMENT START':
                print ("==========================================")
                print (words[0])
                ue_num = 0
            elif words[0] == 'PERFORMANCE MEASUREMENT END':
                """
                print ('send_reg_list:', len(send_reg_list), 'avg:', Average(send_reg_list))
                print ('recv_id_req:', len(recv_id_req), 'avg:', Average(recv_id_req))
                print ('send_id_res:', len(send_id_res), 'avg:', Average(send_id_res))
                print ('recv_auth_req:', len(recv_auth_req), 'avg:', Average(recv_auth_req))
                print ('send_auth_res:', len(send_auth_res), 'avg:', Average(send_auth_res))
                print ('amf_auth_time:', len(amf_auth_time), 'avg:', Average(amf_auth_time))
                print ('recv_sec_mode:', len(recv_sec_mode), 'avg:', Average(recv_sec_mode))
                print ('send_sec_mode:', len(send_sec_mode), 'avg:', Average(send_sec_mode))
                print ('recv_context_setup_req:', len(recv_context_setup_req), 'avg:', Average(recv_context_setup_req))
                print ('send_context_setup_fail:', len(send_context_setup_fail), 'avg:', Average(send_context_setup_fail))
                print ('recv_context_release_cmd:', len(recv_context_release_cmd), 'avg:', Average(recv_context_release_cmd))
                print ('send_context_release_complete:', len(send_context_release_complete), 'avg:', Average(send_context_release_complete))
                """
                print (Average(send_reg_list))
                print (Average(recv_id_req))
                print (Average(send_id_res))
                print (Average(recv_auth_req))
                print (Average(send_auth_res))
                # print (Average(amf_auth_time))
                print (Average(recv_sec_mode))
                print (Average(send_sec_mode))
                print (Average(recv_context_setup_req))
                print (Average(send_context_setup_res))
                print (Average(send_reg_complete))
                print (Average(recv_config_update_cmd))
                print (Average(send_dereg_req))
                # print (Average(send_context_setup_fail))
                print (Average(recv_context_release_cmd))
                print (Average(send_context_release_complete))
                # ue_num = 1
                # first_experiment = False
                send_reg_list = []
                recv_id_req = []
                send_id_res = []        
                recv_auth_req = []
                send_auth_res = []
                amf_auth_time = []            
                recv_sec_mode = []
                send_sec_mode = []
                recv_context_setup_req = []
                send_context_setup_res = []
                send_context_setup_fail = []                
                send_reg_complete = []                
                recv_config_update_cmd = []
                send_dereg_req = []                
                recv_context_release_cmd = []
                send_context_release_complete = []                

            elif words[0].split()[0] == 'ue_id:':
                # print (words)
                ue_num += 1

        elif len(words) == 4:
            if words[1].strip() == 'SEND REGISTRATION REQUEST':
                send_reg_list.append(float(words[3]))
            elif words[1].strip() == 'RECV Identification REQUEST':
                recv_id_req.append(float(words[3]))
            elif words[1].strip() == 'SEND Identification RESPONSE':
                send_id_res.append(float(words[3]))
            elif words[1].strip() == 'RECV AUTH REQUEST':
                recv_auth_req.append(float(words[3]))
            elif words[1].strip() == 'SEND AUTH RESPONSE':
                send_auth_res.append(float(words[3]))
            elif words[1].strip() == 'AMF AUTH TIME':
                amf_auth_time.append(float(words[3]))
            elif words[1].strip() == 'RECV SECURITY MODE COMMAND':
                recv_sec_mode.append(float(words[3]))
            elif words[1].strip() == 'SEND SECURITY MODE COMPLETE':
                send_sec_mode.append(float(words[3]))
            elif words[1].strip() == 'RECV INITIAL CONTEXT SETUP REQUEST':
                recv_context_setup_req.append(float(words[3]))
            elif words[1].strip() == 'SEND INITIAL CONTEXT SETUP FAILURE':
                send_context_setup_fail.append(float(words[3]))
            elif words[1].strip() == 'SEND INITIAL CONTEXT SETUP RESPONSE':
                send_context_setup_res.append(float(words[3]))
            elif words[1].strip() == 'SEND REGISTRATION COMPLETE':
                send_reg_complete.append(float(words[3]))
            elif words[1].strip() == 'RECV CONFIG UPDATE COMMAND':
                recv_config_update_cmd.append(float(words[3]))
            elif words[1].strip() == 'SEND DE-REGISTRATION REQUEST':
                send_dereg_req.append(float(words[3]))
            elif words[1].strip() == 'RECV UE CONTEXT RELEASE COMMAND':
                recv_context_release_cmd.append(float(words[3]))
            elif words[1].strip() == 'SEND UE CONTEXT RELEASE COMPLETE':
                send_context_release_complete.append(float(words[3]))
            else:
                print ("Exception1:", words)
        else:
            # print ("Exception2:", words)
            pass
                   
            
    ###     
    if len(words) == 2:
        #
        # It's a citation
        #
        try:
            #cite = long(words[0])
            # if "CITING" in words[0]:
            #     continue
            print('%s\t%s' % (words[1].strip(), words[0].strip()))
        except Exception as e:
            # improperly formed citation number
            print("Exception ", e);
            pass
    else:
        #
        # It's patent info 
        #
        try:
            # if "PATENT" in words[0]:
            #    continue
            # Delete spaces like '\n' in the last column in Patent Info
            words[-1] = words[-1].strip()
            #cite = long(words[0])
            print('%s\t%s' % (words[0], ','.join(words[1:])))
        except Exception as e:
            # improperly formed citation number
            print("Exception ", e);
            pass
    ###


    
