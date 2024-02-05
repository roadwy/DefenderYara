
rule Ransom_Win64_Hoffee_PAD_MTB{
	meta:
		description = "Ransom:Win64/Hoffee.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 6f 74 43 6f 66 66 65 65 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //01 00 
		$a_81_1 = {48 4f 54 5f 43 4f 46 46 45 45 5f 52 45 41 44 4d 45 2e 68 74 61 } //01 00 
		$a_81_2 = {61 61 61 5f 54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } //01 00 
		$a_01_3 = {70 61 73 73 77 6f 72 64 31 32 33 } //00 00 
	condition:
		any of ($a_*)
 
}