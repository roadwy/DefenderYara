
rule Trojan_BAT_AsyncRAT_T_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 16 00 00 00 55 } //01 00 
		$a_01_1 = {43 6f 6e 66 75 73 65 72 45 78 } //00 00 
	condition:
		any of ($a_*)
 
}