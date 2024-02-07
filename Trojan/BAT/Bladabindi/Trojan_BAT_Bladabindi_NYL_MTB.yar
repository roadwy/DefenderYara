
rule Trojan_BAT_Bladabindi_NYL_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NYL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 65 37 63 62 61 31 61 30 2d 64 37 33 34 2d 34 32 36 38 2d 62 61 31 30 2d 34 61 65 38 62 34 39 64 37 32 30 30 } //01 00  $e7cba1a0-d734-4268-ba10-4ae8b49d7200
		$a_01_1 = {57 95 a2 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9a 00 00 00 1c 00 00 00 58 00 00 00 78 01 00 00 3b 00 00 00 } //01 00 
		$a_01_2 = {0a 01 00 00 7c 00 00 00 02 00 00 00 38 00 00 00 07 00 00 00 28 00 00 00 3e 00 00 00 08 00 00 00 01 00 00 00 0c 00 00 00 } //01 00 
		$a_01_3 = {41 6e 6f 6e 5f 53 45 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //01 00  Anon_SE.Resources.resource
		$a_01_4 = {43 6f 6e 66 75 73 65 72 45 78 20 76 31 } //00 00  ConfuserEx v1
	condition:
		any of ($a_*)
 
}