
rule Trojan_BAT_AgentTesla_MBFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 0b 08 11 08 1f 16 5d 91 61 07 11 0a 91 59 20 00 01 00 00 58 20 00 01 00 00 5d } //01 00 
		$a_01_1 = {51 75 61 6e 6c 79 4e 68 61 68 61 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //00 00  QuanlyNhahang.Properties.Resources.resource
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MBFA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 00 cc 06 59 00 46 06 86 06 } //01 00 
		$a_01_1 = {48 65 6c 70 65 72 5f 43 6c 61 73 73 65 73 } //01 00  Helper_Classes
		$a_01_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_5 = {43 6f 6d 70 75 74 65 48 61 73 68 } //01 00  ComputeHash
		$a_01_6 = {4a 61 6d 62 6f } //01 00  Jambo
		$a_01_7 = {50 61 6e 74 6f 6c 65 } //01 00  Pantole
		$a_01_8 = {4f 7a 75 6f } //00 00  Ozuo
	condition:
		any of ($a_*)
 
}