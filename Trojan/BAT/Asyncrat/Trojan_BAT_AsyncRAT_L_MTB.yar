
rule Trojan_BAT_AsyncRAT_L_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //02 00  server.Resources.resources
		$a_01_1 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //02 00  ConfusedByAttribute
		$a_01_2 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 16 00 00 00 56 00 00 00 9c } //00 00 
	condition:
		any of ($a_*)
 
}