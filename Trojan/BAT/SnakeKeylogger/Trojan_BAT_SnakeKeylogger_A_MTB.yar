
rule Trojan_BAT_SnakeKeylogger_A_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 50 30 30 30 30 30 30 30 30 30 30 30 30 30 30 31 } //2 PP000000000000001
		$a_01_1 = {57 69 6e 64 6f 77 73 41 70 70 31 } //2 WindowsApp1
		$a_01_2 = {4b 30 30 30 30 30 31 } //2 K000001
		$a_01_3 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 } //1 GetMethod
		$a_01_4 = {47 65 74 54 79 70 65 73 } //1 GetTypes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}