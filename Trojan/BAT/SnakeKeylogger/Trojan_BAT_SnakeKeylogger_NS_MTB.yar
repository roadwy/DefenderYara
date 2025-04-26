
rule Trojan_BAT_SnakeKeylogger_NS_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 06 6f 1a 00 00 0a 08 07 6f 1b 00 00 0a 08 6f 1c 00 00 0a 0d 73 1d 00 00 0a 25 09 03 16 03 8e 69 6f 1e 00 00 0a 6f 1f 00 00 0a 13 04 } //2
		$a_01_1 = {28 05 00 00 0a 03 6f 06 00 00 0a 0a 06 14 28 07 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_SnakeKeylogger_NS_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {01 00 00 34 01 00 00 1e 03 00 00 33 00 00 00 0d 00 00 00 b7 00 00 00 64 01 00 00 0d 00 00 00 10 00 00 00 01 00 } //1
		$a_01_1 = {57 15 a2 0b 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9a 00 00 00 15 00 00 00 c4 00 00 00 5f 03 00 00 12 } //1
		$a_01_2 = {42 75 67 54 72 61 63 6b 65 72 46 69 6e 61 6c 50 72 6f 6a 65 63 74 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 BugTrackerFinalProject.Resources.resource
		$a_01_3 = {07 00 00 00 05 00 00 00 05 00 00 00 05 00 00 00 0f 00 00 00 02 00 00 00 00 00 01 } //1
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}