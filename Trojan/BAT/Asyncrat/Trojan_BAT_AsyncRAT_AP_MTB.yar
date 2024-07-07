
rule Trojan_BAT_AsyncRAT_AP_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 94 02 28 c9 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 31 00 00 00 17 00 00 00 58 00 00 00 9e } //2
		$a_01_1 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 server.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}