
rule Ransom_MSIL_CobraLocker_DC_MTB{
	meta:
		description = "Ransom:MSIL/CobraLocker.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 6f 62 72 61 5f 4c 6f 63 6b 65 72 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00 
		$a_81_2 = {73 65 74 5f 46 69 6c 65 4e 61 6d 65 } //01 00 
		$a_81_3 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //01 00 
		$a_81_4 = {47 65 74 46 69 6c 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}