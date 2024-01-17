import sys
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QTableWidgetItem
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from ssh_ui import Ui_MainWindow
import paramiko
import subprocess
import ipaddress
#=========================================================================================================
bpi_count = 0
rpi_count = 0
cmd_adj  = ''
cmd = ''
ipaddress_local = []
#=========================================================================================================
class SSHThread(QThread):
    finished = pyqtSignal(list)

    def __init__(self, hostname, username, password, commands):
        super().__init__()
        self.hostname = hostname
        self.username = username
        self.password = password
        self.commands = commands
#=========================================================================================================
    def run(self):
        try:
            # Create an SSH client
            ssh_client = paramiko.SSHClient()

            # Automatically add the server's host key
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect to the Raspberry Pi
            ssh_client.connect(self.hostname, username=self.username, password=self.password)

            # Execute commands
            results = []
            for command in self.commands:
                # Run the command with sudo
                sudo_command = f"echo '{self.password}' | sudo -S {command}"
                stdin, stdout, stderr = ssh_client.exec_command(sudo_command)

                # Get the output of the command
                result = stdout.read().decode('utf-8')
                results.append(result)

            # Emit the result signal
            self.finished.emit(results)

            # Close the SSH connection
            ssh_client.close()

        except Exception as e:
            self.finished.emit([f"An error occurred: {str(e)}"])
#=========================================================================================================
class MyMainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setWindowTitle("Almost Deploy-TEST")
        # Connect the button click event 
        self.ui.ssh_butt.clicked.connect(lambda : self.run_commands())
        self.ui.arp_butt.clicked.connect(lambda : self.scan_ipaddress())
        self.ui.rst_butt.clicked.connect(lambda : self.rst_commands())
        self.ui.shd_butt.clicked.connect(lambda : self.shd_commands())
        self.ssh_thread = None
    # SCAN IP ADDRESS ======================================================================================================================
    def scan_ipaddress(self):     
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
        self.get_arp_table()
    # GET ARP DATA =========================================================================================================================
    def get_arp_table(self):
        global bpi_count
        global rpi_count
        try:
            # Run the 'arp -a' command and capture the output ============================================================================
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=True)
            # Split the output into lines and store it in an array =======================================================================
            arp_table_lines = result.stdout.strip().splitlines()
            # Extract relevant information from each line ================================================================================
            arp_entries = []
            self.ui.edge_ip_comb.clear()
            for line in arp_table_lines:
                parts = line.split()
                if len(parts) == 3:  # Expected format: Internet Address      Physical Address      Type
                    ip_address  = parts[0]
                    mac_address = parts[1]
                    type_device = parts[2]
                    if parts[2] == 'static' or parts[2] == 'dynamic'  :
                        if parts[1].startswith('c4-3c-b0') or parts[1].startswith('60-fb-00') :
                            parts[2] = 'Banana Pi'
                            type_device = parts[2]
                            arp_entries.append({'IP Address': ip_address, 'MAC Address': mac_address, 'Type Device' : type_device})
                            bpi_count = len(parts[2])
                            combo_show = ip_address + " [" + type_device + "]"
                            self.ui.edge_ip_comb.addItem(combo_show)
                        elif parts[1].startswith('e4-5f-01') or parts[1].startswith('d8-3a-dd') :  # Wait for Device #####################################################
                            parts[2] = 'RasPi'
                            type_device = parts[2]
                            arp_entries.append({'IP Address': ip_address, 'MAC Address': mac_address, 'Type Device' : type_device})
                            rpi_count = len(parts[2])
                            combo_show = ip_address + " [" + type_device + "]" 
                            self.ui.edge_ip_comb.addItem(combo_show )
                        else :
                            pass
                            self.ui.arp_stat_label.setText("Edge Devices Not Found")
                            self.ui.arp_stat_label.setStyleSheet("color : red ;")
                    else :
                            self.ui.arp_stat_label.setText("Edge Devices Not Found")
                            self.ui.arp_stat_label.setStyleSheet("color : red ;")
            if bpi_count > 0 or rpi_count > 0 :
                self.ui.arp_stat_label.setText("Edge Devices Found")
                self.ui.arp_stat_label.setStyleSheet("color : Green ;")
            return arp_entries
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            return None
    # SHOW ARP DATA =========================================================================================================================
    def show_arp_table(self):
        arp_table = self.get_arp_table()
        if arp_table:
            self.ui.arp_tableWidget.setRowCount(len(arp_table))
            self.ui.arp_tableWidget.setColumnCount(3)
            self.ui.arp_tableWidget.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Type Device"])
            for row, entry in enumerate(arp_table):
                ip_item = QTableWidgetItem(entry['MAC Address'])
                mac_item = QTableWidgetItem(entry['IP Address'])
                type_item = QTableWidgetItem(entry['Type Device'])
                self.ui.arp_tableWidget.setItem(row, 0, mac_item)
                self.ui.arp_tableWidget.setItem(row, 1, ip_item)
                self.ui.arp_tableWidget.setItem(row, 2, type_item)
    #=========================================================================================================================================
    # RUN SSH Command ====================================================================
    def run_commands(self):
        global cmd_adj
        # Replace these values with your Raspberry Pi's details
        edge_ip = self.ui.edge_ip_comb.currentText()
        hostname = edge_ip[0:15]
        hostname = "".join(hostname.split())
        username = 'trinity'
        password = self.ui.edge_pass_op.text()
        if password == '' :
            password = 'trinity'
        else :
            password = self.ui.edge_pass_op.text()
        if hostname == '' :
            self.ui.ssh_stat_label.setText("  Device Not Found")
            self.ui.ssh_stat_label.setStyleSheet("color : RED;")
            return 
        # Specify the commands to run
        cmd = self.ui.edge_ip_comb.currentText()
        cmd_adj = cmd[16:21]
        print(cmd_adj)
        if cmd_adj.startswith('Ban') :
            commands = [
                'sudo ifconfig | grep "txqueuelen 1000"',
                'sudo cat GreengrassInstaller/config.yaml | grep "thingName" ',
                'sudo cat /etc/wpa_supplicant/wpa_supplicant.conf | grep "ssid"',
                'sudo df -h | grep "/dev/" ',
                ' docker ps | wc -l',
                'docker ps --format "table {{.Names}}"',
            ]
        elif cmd_adj.startswith('Ras') :
            commands = [
                'sudo cat /proc/cpuinfo | grep "Serial"',
                'sudo cat GreengrassInstaller/config.yaml | grep "thingName" ',
                'sudo cat /etc/wpa_supplicant/wpa_supplicant.conf | grep "ssid"',
                'sudo df -h | grep "/dev/" ',
                ' docker ps | wc -l',
                'docker ps --format "table {{.Names}}"',
            ]
        elif cmd_adj.startswith('asPi') :
            commands = [
                'sudo cat /proc/cpuinfo | grep "Serial"',
                'sudo cat GreengrassInstaller/config.yaml | grep "thingName" ',
                'sudo cat /etc/wpa_supplicant/wpa_supplicant.conf | grep "ssid"',
                'sudo df -h | grep "/dev/" ',
                ' docker ps | wc -l',
                'docker ps --format "table {{.Names}}"',
            ]
        elif cmd_adj.startswith('anan') :
            commands = [
                'sudo ifconfig | grep "txqueuelen 1000"',
                'sudo cat GreengrassInstaller/config.yaml | grep "thingName" ',
                'sudo cat /etc/wpa_supplicant/wpa_supplicant.conf | grep "ssid"',
                'sudo df -h | grep "/dev/" ',
                ' docker ps | wc -l',
                'docker ps --format "table {{.Names}}"',
            ]
        else : 
            print("Exit")
            return
        # Create and start the SSH thread
        self.clear_ui()
        self.ui.ssh_stat_label.setText("  SSH On Progress")
        self.ui.ssh_stat_label.setStyleSheet("color : Green;")
        self.ssh_thread = SSHThread(hostname, username, password, commands)
        self.ssh_thread.finished.connect(self.display_results)
        self.ssh_thread.start()
    # SHOW SSH Data =====================================================================
    def display_results(self, results):
        global cmd_adj
        # Specify the commands to run
        commands = [    'Device ID',
                        'ThingName',
                        'WiFi',
                        'Storage',
                        'Docker Num',
                        'Docker Name'   ]
        # Populate the table with command and result
        for i, (command, result) in enumerate(zip(commands, results)):
            if i == 0 :
                mac_id = result
                if cmd_adj.startswith('Ban') :
                    mac_id = result[75:93]
                    if str(mac_id).startswith("c4:") or str(mac_id).startswith("60:") :
                        self.ui.inspec_tableWidget.setItem(0, 0, QTableWidgetItem(mac_id))
                    elif str(mac_id) == "" :
                        self.clear_tab()
                        self.clear_ui()
                        self.ui.ssh_stat_label.setText(" SSH FAIL : Please check your Password")
                        self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                        break
                    elif str(mac_id).startswith(' connected party d') :
                        self.clear_tab()
                        self.ui.ssh_stat_label.setText(" This Device Already OFFLINE : Ensure IT")
                        self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                        break
                    else :
                        self.clear_tab()
                        self.ui.ssh_stat_label.setText(" SSH FAIL : Please check your Password")
                        self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                elif cmd_adj.startswith('Ras') :
                    mac_id = result[10:26]
                    if str(mac_id).startswith("10000") :
                        self.ui.inspec_tableWidget.setItem(0, 0, QTableWidgetItem(mac_id))
                    elif str(mac_id) == "" :
                        self.clear_tab()
                        self.ui.ssh_stat_label.setText(" SSH FAIL : Please check your Password")
                        self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                        break
                    elif str(mac_id).startswith(' connected party d') :
                        self.clear_tab()
                        self.ui.ssh_stat_label.setText(" This Device Already OFFLINE : Ensure IT")
                        self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                        break
                elif cmd_adj.startswith('asPi') :
                    mac_id = result[10:26]
                    if str(mac_id).startswith("10000") :
                        self.ui.inspec_tableWidget.setItem(0, 0, QTableWidgetItem(mac_id))
                    elif str(mac_id) == "" :
                        self.clear_tab()
                        self.ui.ssh_stat_label.setText(" SSH FAIL : Please check your Password")
                        self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                        break
                    elif str(mac_id).startswith(' connected party d') :
                        self.clear_tab()
                        self.ui.ssh_stat_label.setText(" This Device Already OFFLINE : Ensure IT")
                        self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                        break
                    else :
                        self.clear_tab()
                        self.ui.ssh_stat_label.setText(" SSH FAIL : Please check your Password")
                        self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                elif cmd_adj.startswith('anana') :
                    mac_id = result[75:93]
                    if str(mac_id).startswith("c4:") or str(mac_id).startswith("60:") :
                        self.ui.inspec_tableWidget.setItem(0, 0, QTableWidgetItem(mac_id))
                    elif str(mac_id) == "" :
                        self.clear_tab()
                        self.ui.ssh_stat_label.setText(" SSH FAIL : Please check your Password")
                        self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                        break
                    elif str(mac_id).startswith(' connected party d') :
                        self.clear_tab()
                        self.ui.ssh_stat_label.setText(" This Device Already OFFLINE : Ensure IT")
                        self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                        break
                    else :
                        self.clear_tab()
                        self.ui.ssh_stat_label.setText(" SSH FAIL : Please check your Password")
                        self.ui.ssh_stat_label.setStyleSheet("color : RED;")
            if i == 1 :
                thing_name = result
                if cmd_adj.startswith('Ban') :
                    thing_name = result[14:31]
                    self.ui.inspec_tableWidget.setItem(1, 0, QTableWidgetItem(thing_name))
                elif cmd_adj.startswith('Ras') :
                    thing_name = result[14:33]
                    self.ui.inspec_tableWidget.setItem(1, 0, QTableWidgetItem(thing_name))
                elif cmd_adj.startswith('asPi') :
                    thing_name = result[14:33]
                    self.ui.inspec_tableWidget.setItem(1, 0, QTableWidgetItem(thing_name))
                elif cmd_adj.startswith('anan') :
                    thing_name = result[14:31]
                    self.ui.inspec_tableWidget.setItem(1, 0, QTableWidgetItem(thing_name))
            if i == 2 :
                edge_ssid = result
                edge_ssid = "".join(edge_ssid.split())
                edge_ssid = edge_ssid[6:12]
                self.ui.inspec_tableWidget.setItem(2, 0, QTableWidgetItem(edge_ssid))
            if i == 3 :
                sd_card = result[16:20]+"B"
                self.ui.inspec_tableWidget.setItem(3, 0, QTableWidgetItem(sd_card))
            if i == 4 :
                docker_num = result[0:1]
                docker_int= int(docker_num)-1
                self.ui.inspec_tableWidget.setItem(4, 0, QTableWidgetItem(str(docker_int)))
            if i == 5 :
                self.ui.docker_list.setPlainText(result)
                self.ui.ssh_stat_label.setText(" SSH Device Show Results")
                self.ui.ssh_stat_label.setStyleSheet("color : Green;")
    # Reboot ============================================================================
    def rst_commands(self):
        # Replace these values with Pi's details
        edge_ip = self.ui.edge_ip_comb.currentText()
        hostname = edge_ip[0:15]
        hostname = "".join(hostname.split())
        username = 'trinity'
        password = self.ui.edge_pass_op.text()
        if password == '' :
            password = 'trinity'
        else :
            password = self.ui.edge_pass_op.text()
        if hostname == '' :
            self.ui.ssh_stat_label.setText("  Device Not Found")
            self.ui.ssh_stat_label.setStyleSheet("color : RED;")
            return 
        # Specify the commands to run
        cmd = self.ui.edge_ip_comb.currentText()
        cmd_adj = cmd[17:22]
        if cmd_adj.startswith('Ban') :
            commands = ['sudo ifconfig | grep "txqueuelen 1000"' , 'sudo reboot']
        elif cmd_adj.startswith('Ras') :
            commands = ['sudo cat /proc/cpuinfo | grep "Serial"' , 'sudo reboot']
        elif cmd_adj.startswith('asPi') :
            commands = ['sudo ifconfig | grep "txqueuelen 1000"' , 'sudo reboot']
        elif cmd_adj.startswith('anan') :
            commands = ['sudo cat /proc/cpuinfo | grep "Serial"' , 'sudo reboot']
        else : 
            print("Exit")
            return
        # Create and start the SSH thread
        self.clear_ui()
        self.ui.ssh_stat_label.setText("  Reboot On Progress")
        self.ui.ssh_stat_label.setStyleSheet("color : Green;")
        self.ssh_thread = SSHThread(hostname, username, password, commands)
        self.ssh_thread.finished.connect(self.rst_results)
        self.ssh_thread.start()
    # SHOW SSH Data =====================================================================
    def rst_results(self, results):
        global cmd_adj
        commands = [    'MAC ID', 'Reboot'  ]
        for i, (command, result) in enumerate(zip(commands, results)):
            if i == 0 :
                mac_id = result
                if cmd_adj.startswith('Ban') :
                    mac_id = result[75:93]
                elif cmd_adj.startswith('Ras') :
                    mac_id = result[10:26]
                elif cmd_adj.startswith('anan') :
                    mac_id = result[75:93]
                elif cmd_adj.startswith('asPi') :
                    mac_id = result[10:26]
                if str(mac_id) == "" :
                    self.clear_tab()
                    self.ui.ssh_stat_label.setText(" SSH FAIL : Please check your Password")
                    self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                    break
                elif str(mac_id).startswith(' connected party d') :
                    self.clear_tab()
                    self.ui.ssh_stat_label.setText(" This Device Already OFFLINE : Ensure IT")
                    self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                    break
            if i == 1 :
                self.clear_tab()
                self.ui.ssh_stat_label.setText("  This Device Already Reboot")
                self.ui.ssh_stat_label.setStyleSheet("color : Green;")
    # SHUTDOWN ===========================================================================
    def shd_commands(self):
        # Replace these values with your Raspberry Pi's details
        edge_ip = self.ui.edge_ip_comb.currentText()
        hostname = edge_ip[0:15]
        hostname = "".join(hostname.split())
        username = 'trinity'
        password = self.ui.edge_pass_op.text()
        if password == '' :
            password = 'trinity'
        else :
            password = self.ui.edge_pass_op.text()
        if hostname == '' :
            self.ui.ssh_stat_label.setText("  Device Not Found")
            self.ui.ssh_stat_label.setStyleSheet("color : RED;")
            return 

        # Specify the commands to run
        cmd = self.ui.edge_ip_comb.currentText()
        cmd_adj = cmd[17:22]
        if cmd_adj.startswith('Ban') :
            commands = ['sudo ifconfig | grep "txqueuelen 1000"' , 'sudo shutdown now']
        elif cmd_adj.startswith('Ras') :
            commands = ['sudo cat /proc/cpuinfo | grep "Serial"' , 'sudo shutdown now']
        elif cmd_adj.startswith('anan') :
            commands = ['sudo ifconfig | grep "txqueuelen 1000"' , 'sudo shutdown now']
        elif cmd_adj.startswith('asPi') :
            commands = ['sudo cat /proc/cpuinfo | grep "Serial"' , 'sudo shutdown now']
        else : 
            print("Exit")
            return
        # Create and start the SSH thread
        self.clear_ui()
        self.ui.ssh_stat_label.setText("  Shutdown On Progress")
        self.ui.ssh_stat_label.setStyleSheet("color : Green;")
        self.ssh_thread = SSHThread(hostname, username, password, commands)
        self.ssh_thread.finished.connect(self.shd_results)
        self.ssh_thread.start()
    # SHOW SSH Data =====================================================================
    def shd_results(self, results):
        commands = [    'MAC ID', 'Shutdown'  ]
        for i, (command, result) in enumerate(zip(commands, results)):
            if i == 0 :
                mac_id = result
                if cmd_adj.startswith('Ban') :
                    mac_id = result[75:93]
                elif cmd_adj.startswith('Ras') :
                    mac_id = result[10:26]
                elif cmd_adj.startswith('anan') :
                    mac_id = result[75:93]
                elif cmd_adj.startswith('asPi') :
                    mac_id = result[10:26]
                if str(mac_id) == "" :
                    self.clear_tab()
                    self.ui.ssh_stat_label.setText(" SSH FAIL : Please check your Password")
                    self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                    break
                elif str(mac_id).startswith(' connected party d') :
                    self.clear_tab()
                    self.ui.ssh_stat_label.setText(" This Device Already OFFLINE : Ensure IT")
                    self.ui.ssh_stat_label.setStyleSheet("color : RED;")
                    break
            if i == 1 :
                self.clear_tab()
                self.clear_ui()
                self.ui.ssh_stat_label.setText("  Shutdown Complete")
                self.ui.ssh_stat_label.setStyleSheet("color : Green;")
    # CLear Table View and All ================================================================================
    def clear_ui(self) : 
        self.ui.edge_pass_op.clear()
     # End ===============================================================================================
    def clear_tab(self) :
        # Clear WT ================================================
        for row in range(self.ui.inspec_tableWidget.rowCount()):
            for col in range(self.ui.inspec_tableWidget.columnCount()):
                item = QtWidgets.QTableWidgetItem("")
                self.ui.inspec_tableWidget.setItem(row, col, item)
        self.ui.docker_list.clear()
#=========================================================================================================================================
def main():
    app = QtWidgets.QApplication(sys.argv)
    main_window = MyMainWindow()
    main_window.show()
    sys.exit(app.exec_())
        
if __name__ == "__main__":
    # del_file()
    main()
# exit -------------------------------------//
