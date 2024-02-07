
rule Backdoor_Linux_Tusnami_B_xp{
	meta:
		description = "Backdoor:Linux/Tusnami.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 0b 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 6f 75 63 68 20 2f 74 6d 70 2f 67 61 74 65 73 2e 6c 6f 64 } //01 00  touch /tmp/gates.lod
		$a_00_1 = {6b 69 6c 6c 61 6c 6c 20 2d 39 20 74 63 70 64 75 6d 70 } //01 00  killall -9 tcpdump
		$a_00_2 = {6b 69 6c 6c 61 6c 6c 20 2d 39 20 73 74 72 61 63 65 } //01 00  killall -9 strace
		$a_00_3 = {78 78 78 2e 70 6f 6b 65 6d 6f 6e 69 6e 63 2e 63 6f 6d } //02 00  xxx.pokemoninc.com
		$a_00_4 = {75 64 65 76 64 30 2e 70 69 64 } //01 00  udevd0.pid
		$a_00_5 = {63 68 6d 6f 64 20 37 35 35 20 2f 65 74 63 2f 70 65 72 73 69 73 74 65 6e 74 2f 72 63 2e 70 6f 73 74 73 74 61 72 74 } //01 00  chmod 755 /etc/persistent/rc.poststart
		$a_00_6 = {6e 76 72 61 6d 20 73 65 74 20 72 63 5f 66 69 72 65 77 61 6c 6c 3d 22 73 6c 65 65 70 20 31 32 30 20 26 26 20 77 67 65 74 20 2d 71 4f } //01 00  nvram set rc_firewall="sleep 120 && wget -qO
		$a_00_7 = {6b 69 6c 6c 20 62 61 63 6b 67 72 6f 75 6e 64 20 74 68 72 65 61 64 73 20 6f 72 20 63 75 72 72 65 6e 74 20 70 61 63 6b 65 74 69 6e 67 } //01 00  kill background threads or current packeting
		$a_00_8 = {63 6f 6e 6e 65 63 74 62 61 63 6b 20 73 68 65 6c 6c 20 32 5f 39 30 36 32 30 31 35 } //01 00  connectback shell 2_9062015
		$a_00_9 = {4e 4f 54 49 43 45 20 25 73 20 3a 6b 74 68 72 2e 73 73 68 } //01 00  NOTICE %s :kthr.ssh
		$a_00_10 = {58 4d 41 53 20 3c 74 61 72 67 65 74 3e 20 3c 70 6f 72 74 3e 20 3c 73 65 63 73 3e 20 3c 63 77 72 2c 65 63 65 2c 75 72 67 2c 61 63 6b 2c 70 73 68 2c 72 73 74 2c 66 69 6e 2c 73 79 6e 20 6f 72 20 6e 75 6c 6c } //00 00  XMAS <target> <port> <secs> <cwr,ece,urg,ack,psh,rst,fin,syn or null
	condition:
		any of ($a_*)
 
}