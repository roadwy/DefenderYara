
rule Backdoor_Linux_Gafgyt_BE_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 90 02 15 2f 90 02 10 20 7c 7c 20 63 75 72 6c 20 2d 4f 20 68 74 74 70 3a 2f 2f 90 02 15 2f 90 02 10 3b 20 63 68 6d 6f 64 20 37 37 37 90 00 } //01 00 
		$a_00_1 = {72 6d 20 2d 72 66 20 2f 76 61 72 2f 6c 6f 67 2f 77 74 6d 70 } //01 00  rm -rf /var/log/wtmp
		$a_00_2 = {70 6b 69 6c 6c 20 2d 39 20 62 75 73 79 62 6f 78 } //01 00  pkill -9 busybox
		$a_01_3 = {42 4f 54 4b 49 4c 4c } //01 00  BOTKILL
		$a_01_4 = {54 45 4c 4e 45 54 20 4f 4e 20 7c 20 4f 46 46 } //00 00  TELNET ON | OFF
	condition:
		any of ($a_*)
 
}