
rule Ransom_MSIL_SADRAN_DA_MTB{
	meta:
		description = "Ransom:MSIL/SADRAN.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //01 00 
		$a_01_1 = {53 41 44 20 52 41 4e 53 4f 4d 57 41 52 45 } //01 00 
		$a_01_2 = {4d 6f 72 65 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 61 62 6f 75 74 20 42 69 74 63 6f 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}