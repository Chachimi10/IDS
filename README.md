# IDS
Creation of a simple IDS for a school project 
This programme uses mainly libpcap to capture packets transiting through an interface. 
Then it put those packages in a frame that can be use later. 
This programm contains 2 other important functions : Read_Rules and Rule_Matcher. 

The first one will read the rules from a file in arguments to make a structure.
The second will use the overmentionned rule structure and compare it to the custom frame created earlier. 
If some parameters match between the two, an alert is written in the syslog. 


Currently this programm is only working on Linux. 
It supports only 3 types of alert : 

Protocol used is http and the payload contains the string "malware.exe" : the programm will return "Shell Attack" ;
Protocol used is tcp and destination port is 8888 : the programm will return "Backdoor Attack" ;
Protocol used is udp and destination port is 9999 : the programm will return "UDP trafic bind port is forbidden".

4 Files are used in this programm : 
Main.c contains the 2 functions Read_Rules and Rule_Matcher plus the packet handler. You also have the definition of the structure used by Read_rules.
Populate.h is mainly use to define the frame used by populate.c 
Populate.c will, as his name suggests, populate the frame with the packages caught by the packet handler. 
ids.rules contains a sample of rules that can be used by the program. It's the file used by default.

The populate.c, populate.h, ids.rule and parts of main.c file were written by Henallux teachers
The rest of the main.c file was written by Riccardo B. and Charles D.



