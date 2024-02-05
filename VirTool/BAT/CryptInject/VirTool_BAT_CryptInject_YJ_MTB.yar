
rule VirTool_BAT_CryptInject_YJ_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.YJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 6c 00 73 00 4f 00 6c 00 64 00 52 00 75 00 6e 00 50 00 65 00 } //01 00 
		$a_01_1 = {52 65 67 50 65 72 73 69 73 74 61 6e 63 65 } //01 00 
		$a_01_2 = {52 75 6e 50 65 72 73 69 73 74 65 6e 63 65 } //01 00 
		$a_01_3 = {2e 56 6d 44 65 74 65 63 74 6f 72 2e 57 69 6e 33 32 } //01 00 
		$a_01_4 = {46 69 6c 65 50 65 72 73 69 73 74 61 6e 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}