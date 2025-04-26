
rule Backdoor_Linux_Tusnami_F_xp{
	meta:
		description = "Backdoor:Linux/Tusnami.F!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {75 6e 6b 6e 6f 77 6e 20 3c 74 61 72 67 65 74 3e 20 3c 70 6f 72 74 3e 20 3c 74 69 6d 65 3e 20 3c 74 68 72 65 61 64 73 3e 20 3c 2f 73 68 69 74 2e 70 68 70 } //1 unknown <target> <port> <time> <threads> </shit.php
		$a_00_1 = {67 72 65 70 20 2d 76 20 22 6c 65 73 73 68 74 73 2f 72 75 6e 2e 73 68 22 20 3e 20 25 73 2f 2e 78 30 30 25 75 } //1 grep -v "lesshts/run.sh" > %s/.x00%u
		$a_00_2 = {63 6f 6e 6e 65 63 74 62 61 63 6b 20 73 68 65 6c 6c } //1 connectback shell
		$a_00_3 = {68 61 6e 64 79 20 64 6f 77 6e 6c 6f 61 64 65 72 } //1 handy downloader
		$a_00_4 = {57 65 6c 63 6f 6d 65 20 74 6f 20 78 30 30 27 73 20 63 62 61 63 6b 20 73 68 65 6c 6c } //1 Welcome to x00's cback shell
		$a_00_5 = {6d 79 73 74 65 72 69 6f 75 73 20 6c 61 79 65 72 37 20 61 74 74 61 63 6b 2c 20 77 65 62 73 69 74 65 73 20 61 72 65 20 6b 69 6c 6c } //1 mysterious layer7 attack, websites are kill
		$a_00_6 = {55 44 50 20 66 6c 6f 6f 64 } //1 UDP flood
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}