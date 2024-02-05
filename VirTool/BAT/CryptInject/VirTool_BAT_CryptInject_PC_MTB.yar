
rule VirTool_BAT_CryptInject_PC_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.PC!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 6f 72 44 65 63 72 79 70 74 } //01 00 
		$a_01_1 = {50 6f 6c 79 56 44 65 63 72 79 70 74 } //01 00 
		$a_01_2 = {44 65 63 72 79 70 74 42 69 74 6d 61 70 } //01 00 
		$a_01_3 = {44 65 63 72 79 70 74 49 6d 61 67 65 } //01 00 
		$a_01_4 = {44 65 63 72 79 70 74 69 6f 6e 4b 65 79 49 } //00 00 
	condition:
		any of ($a_*)
 
}