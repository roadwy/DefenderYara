
rule Backdoor_Linux_Mirai_S_xp{
	meta:
		description = "Backdoor:Linux/Mirai.S!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {4b 49 4c 4c 42 4f 54 } //01 00  KILLBOT
		$a_01_1 = {31 39 32 2e 32 33 36 2e 31 39 35 2e 32 31 32 } //01 00  192.236.195.212
		$a_01_2 = {6d 69 6f 72 69 20 72 65 6d 61 73 74 65 72 65 64 } //01 00  miori remastered
		$a_01_3 = {55 44 50 52 41 57 } //01 00  UDPRAW
		$a_01_4 = {47 65 6e 6f 63 69 64 65 20 42 6f 74 6e 65 74 } //01 00  Genocide Botnet
		$a_01_5 = {31 38 35 2e 31 37 32 2e 31 31 30 2e 32 33 30 } //01 00  185.172.110.230
		$a_01_6 = {34 35 2e 39 35 2e 31 36 38 2e 39 36 } //01 00  45.95.168.96
		$a_01_7 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //01 00  /bin/busybox
		$a_01_8 = {61 6e 74 69 68 6f 6e 65 79 } //00 00  antihoney
		$a_00_9 = {5d 04 00 } //00 d7 
	condition:
		any of ($a_*)
 
}