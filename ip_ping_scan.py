import ipaddress
import subprocess

ipaddress_local = []

def scan_ipaddress_():    
    
    start_ip ="192.168.1.0"
    subnet_mask = "/24"
    # Create the network
    net_ip = start_ip + subnet_mask
    #print(net_ip)
    ip = ipaddress.ip_network(net_ip)
    all_hosts = list(ip.hosts())
    info = subprocess.STARTUPINFO()
    for i in range(1,254):
        output = subprocess.Popen(['ping', '-n', '1', '-w', '200', str(all_hosts[i])], stdout=subprocess.PIPE, startupinfo=info).communicate()[0]
        # -n = count of sent packets   -w = delay (ms)       
        if "Request timed out" in output.decode('utf-8'):
            
            print("\n"+str(all_hosts[i]), "is Offline")
            print("----------------------------------------")
            
        else:
            # print(str(all_hosts[i]), "is Online ---> ")
            ipaddress_local.append(str(all_hosts[i]))
            print(str(all_hosts[i]))

if __name__=="__main__":
    scan_ipaddress_()