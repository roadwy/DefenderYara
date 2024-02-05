
rule VirTool_BAT_CryptInject_AW_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.AW!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 45 6e 63 72 79 70 74 65 64 } //01 00 
		$a_01_1 = {53 74 65 61 6c 44 42 2e 65 78 65 } //01 00 
		$a_01_2 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00 
		$a_01_3 = {5c 00 50 00 61 00 73 00 73 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_4 = {52 43 32 44 65 63 72 79 70 74 } //01 00 
		$a_01_5 = {53 74 65 61 6c 44 42 2e 4d 79 } //00 00 
	condition:
		any of ($a_*)
 
}