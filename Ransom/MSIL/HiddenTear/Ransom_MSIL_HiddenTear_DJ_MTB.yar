
rule Ransom_MSIL_HiddenTear_DJ_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 6e 63 72 79 70 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 64 } //01 00 
		$a_81_1 = {48 69 64 64 65 6e 54 65 61 72 } //01 00 
		$a_81_2 = {2e 6c 6f 63 6b 65 64 } //01 00 
		$a_81_3 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 64 69 73 61 62 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}