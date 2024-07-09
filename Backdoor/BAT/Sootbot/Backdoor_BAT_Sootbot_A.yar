
rule Backdoor_BAT_Sootbot_A{
	meta:
		description = "Backdoor:BAT/Sootbot.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 45 78 65 63 75 74 65 } //1 DlExecute
		$a_01_1 = {74 63 70 52 61 6e 64 6f 6d } //1 tcpRandom
		$a_01_2 = {75 64 70 52 61 6e 64 6f 6d } //1 udpRandom
		$a_01_3 = {53 6c 6f 77 6c 6f 72 69 73 } //1 Slowloris
		$a_01_4 = {46 4c 4f 4f 44 5f 53 54 4f 50 } //1 FLOOD_STOP
		$a_03_5 = {1f 1d 12 00 1a 28 ?? 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}
rule Backdoor_BAT_Sootbot_A_2{
	meta:
		description = "Backdoor:BAT/Sootbot.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 45 78 65 63 75 74 65 } //1 DlExecute
		$a_01_1 = {74 63 70 52 61 6e 64 6f 6d } //1 tcpRandom
		$a_01_2 = {75 64 70 52 61 6e 64 6f 6d } //1 udpRandom
		$a_01_3 = {53 6c 6f 77 6c 6f 72 69 73 } //1 Slowloris
		$a_01_4 = {73 00 30 00 30 00 74 00 62 00 30 00 74 00 } //1 s00tb0t
		$a_01_5 = {46 00 6c 00 6f 00 6f 00 64 00 20 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 40 00 40 00 } //1 Flood started @@
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}