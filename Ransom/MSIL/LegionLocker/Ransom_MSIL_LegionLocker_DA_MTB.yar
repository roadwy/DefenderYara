
rule Ransom_MSIL_LegionLocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/LegionLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {4c 65 67 69 6f 6e 4c 6f 63 6b 65 72 32 2e 31 } //01 00 
		$a_81_1 = {40 2e 74 68 65 6d 69 64 61 } //01 00 
		$a_81_2 = {58 42 75 6e 64 6c 65 72 54 6c 73 48 65 6c 70 65 72 } //01 00 
		$a_81_3 = {73 6b 69 70 61 63 74 69 76 65 78 72 65 67 } //01 00 
		$a_81_4 = {57 69 6e 4c 69 63 65 6e 73 65 49 6e 73 74 61 6e 63 65 } //01 00 
		$a_81_5 = {6c 6f 67 73 74 61 74 75 73 } //00 00 
	condition:
		any of ($a_*)
 
}