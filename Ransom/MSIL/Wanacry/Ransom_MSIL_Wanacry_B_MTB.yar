
rule Ransom_MSIL_Wanacry_B_MTB{
	meta:
		description = "Ransom:MSIL/Wanacry.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 46 69 6c 65 73 20 48 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_81_1 = {53 68 61 72 65 57 61 72 65 5f 52 61 6e 73 6f 6d 77 61 72 65 } //01 00 
		$a_81_2 = {57 61 6e 61 63 72 79 74 6f 72 } //01 00 
		$a_81_3 = {45 74 68 65 72 65 75 6d 20 41 64 72 65 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}