
rule Backdoor_Linux_Tusnami_G_xp{
	meta:
		description = "Backdoor:Linux/Tusnami.G!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_00_0 = {75 6e 6b 6e 6f 77 6e 20 3c 74 61 72 67 65 74 3e 20 3c 70 6f 72 74 3e 20 3c 74 69 6d 65 3e 20 3c 74 68 72 65 61 64 73 3e 20 3c 2f 73 68 69 74 2e 70 68 70 } //1 unknown <target> <port> <time> <threads> </shit.php
		$a_02_1 = {77 67 65 74 20 2d 71 4f 20 2d [0-05] 3a 2f 2f 66 6b 64 2e 64 65 72 70 63 69 74 79 2e 72 75 2f 6e 76 72 } //1
		$a_00_2 = {2f 65 74 63 2f 61 75 74 6f 5f 72 75 6e 5f 61 70 70 2e 73 68 20 } //1 /etc/auto_run_app.sh 
		$a_00_3 = {68 61 6e 64 79 20 64 6f 77 6e 6c 6f 61 64 65 72 } //1 handy downloader
		$a_00_4 = {57 65 6c 63 6f 6d 65 20 74 6f 20 78 30 30 27 73 20 63 62 61 63 6b 20 73 68 65 6c 6c } //1 Welcome to x00's cback shell
		$a_00_5 = {2f 65 74 63 2f 69 6e 69 74 2e 64 2f 53 39 39 6e 76 72 61 6b } //1 /etc/init.d/S99nvrak
		$a_00_6 = {2f 76 61 72 2f 72 75 6e 2f 73 68 69 74 2e 62 6b 70 } //1 /var/run/shit.bkp
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=3
 
}