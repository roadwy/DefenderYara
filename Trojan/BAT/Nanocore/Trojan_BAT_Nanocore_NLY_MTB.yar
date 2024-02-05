
rule Trojan_BAT_Nanocore_NLY_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {70 30 2e 6a 4f } //01 00 
		$a_81_1 = {53 48 41 32 35 36 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00 
		$a_81_2 = {4c 6f 67 53 77 69 74 63 68 } //01 00 
		$a_81_3 = {58 43 43 56 56 } //01 00 
		$a_81_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00 
		$a_81_5 = {55 49 50 65 72 6d 69 73 73 69 6f 6e } //01 00 
		$a_81_6 = {43 6f 6d 70 75 74 65 48 61 73 68 } //00 00 
	condition:
		any of ($a_*)
 
}