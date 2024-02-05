
rule Ransom_MSIL_HiddenTear_PL_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //01 00 
		$a_01_1 = {5c 00 52 00 45 00 41 00 44 00 5f 00 49 00 54 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_2 = {59 00 6f 00 72 00 20 00 46 00 69 00 6c 00 65 00 20 00 4c 00 6f 00 63 00 6b 00 65 00 64 00 } //01 00 
		$a_01_3 = {5c 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 2e 00 74 00 78 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}