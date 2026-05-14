
rule Trojan_BAT_AsyncRAT_AP_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 18 91 08 00 0a 20 72 14 00 00 0b 03 04 6e 06 6a 58 05 6e 58 07 6a 58 69 61 10 01 03 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRAT_AP_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 94 02 28 c9 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 31 00 00 00 17 00 00 00 58 00 00 00 9e } //2
		$a_01_1 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 server.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}