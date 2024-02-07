
rule DDoS_Linux_Mirai_PA_MTB{
	meta:
		description = "DDoS:Linux/Mirai.PA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 09 00 00 02 00 "
		
	strings :
		$a_00_0 = {6d 69 72 61 69 } //02 00  mirai
		$a_00_1 = {75 64 70 66 6c 6f 6f 64 } //02 00  udpflood
		$a_00_2 = {74 63 70 66 6c 6f 6f 64 } //02 00  tcpflood
		$a_00_3 = {75 64 70 66 6c 30 30 64 } //02 00  udpfl00d
		$a_00_4 = {74 63 70 66 6c 30 30 64 } //01 00  tcpfl00d
		$a_01_5 = {76 73 65 61 74 74 61 63 6b } //01 00  vseattack
		$a_01_6 = {6b 69 6c 6c 65 72 73 74 6f 72 6d } //01 00  killerstorm
		$a_01_7 = {4b 48 73 65 72 76 65 72 48 41 43 4b 45 52 } //01 00  KHserverHACKER
		$a_01_8 = {68 75 61 77 65 69 73 63 61 6e 6e 65 72 5f 73 63 61 6e 6e 65 72 5f 6b 69 6c 6c } //00 00  huaweiscanner_scanner_kill
		$a_00_9 = {5d 04 00 } //00 0b 
	condition:
		any of ($a_*)
 
}