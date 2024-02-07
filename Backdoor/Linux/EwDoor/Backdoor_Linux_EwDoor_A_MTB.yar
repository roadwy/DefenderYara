
rule Backdoor_Linux_EwDoor_A_MTB{
	meta:
		description = "Backdoor:Linux/EwDoor.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {6b 69 6c 6c 61 6c 6c 20 2d 39 20 6e 65 74 66 6c 61 73 68 20 3e 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 } //01 00  killall -9 netflash >/dev/null 2>&1
		$a_00_1 = {2f 76 61 72 2f 73 6f 63 32 5f 75 70 67 72 61 64 65 2e 6c 6f 63 6b } //01 00  /var/soc2_upgrade.lock
		$a_00_2 = {2f 65 74 63 2f 63 6f 6e 66 69 67 2f 65 77 2e 63 6f 6e 66 } //01 00  /etc/config/ew.conf
		$a_00_3 = {63 70 20 2d 66 20 2f 76 61 72 2f 74 6d 70 2f 2e 6d 6e 74 2f 65 77 75 70 64 61 74 65 20 2f 76 61 72 2f 74 6d 70 2f 2e 6d 6e 74 2f 65 77 73 74 61 74 } //01 00  cp -f /var/tmp/.mnt/ewupdate /var/tmp/.mnt/ewstat
		$a_00_4 = {72 6d 20 2d 66 20 2f 76 61 72 2f 74 6d 70 2f 2e 6d 6e 74 2f 65 77 75 70 64 61 74 65 } //01 00  rm -f /var/tmp/.mnt/ewupdate
		$a_00_5 = {73 74 61 72 74 5f 73 79 6e 5f 66 6c 6f 6f 64 } //01 00  start_syn_flood
		$a_00_6 = {73 74 61 72 74 5f 75 64 70 5f 66 6c 6f 6f 64 } //01 00  start_udp_flood
		$a_00_7 = {2f 74 6d 70 2f 2e 65 77 73 74 61 74 } //00 00  /tmp/.ewstat
	condition:
		any of ($a_*)
 
}