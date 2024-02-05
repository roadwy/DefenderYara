
rule Ransom_MSIL_Anubis_DA_MTB{
	meta:
		description = "Ransom:MSIL/Anubis.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6e 75 62 69 73 } //01 00 
		$a_81_1 = {51 57 35 31 59 6d 6c 7a 4a 51 3d 3d } //01 00 
		$a_81_2 = {5f 45 6e 63 72 79 70 74 65 64 24 } //01 00 
		$a_81_3 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 57 } //00 00 
	condition:
		any of ($a_*)
 
}