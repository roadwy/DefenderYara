
rule Ransom_Win64_Baphomet_DA_MTB{
	meta:
		description = "Ransom:Win64/Baphomet.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 42 61 70 68 6f 6d 65 74 } //01 00 
		$a_81_1 = {67 65 74 2e 70 68 70 } //01 00 
		$a_81_2 = {79 6f 75 72 6b 65 79 2e 6b 65 79 } //01 00 
		$a_81_3 = {65 6e 63 72 79 70 74 46 69 6c 65 44 61 74 61 } //01 00 
		$a_81_4 = {50 61 73 74 65 20 70 75 62 6c 69 63 20 72 73 61 20 6b 65 79 20 68 65 72 65 } //00 00 
	condition:
		any of ($a_*)
 
}