
rule Ransom_Win32_CONTI_DA_MTB{
	meta:
		description = "Ransom:Win32/CONTI.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 63 75 72 72 65 6e 74 6c 79 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 43 4f 4e 54 49 20 73 74 72 61 69 6e } //01 00 
		$a_81_1 = {59 4f 55 20 53 48 4f 55 4c 44 20 42 45 20 41 57 41 52 45 21 } //01 00 
		$a_81_2 = {2e 6f 6e 69 6f 6e } //01 00 
		$a_81_3 = {68 74 74 70 73 3a 2f 2f 63 6f 6e 74 69 72 65 63 6f 76 65 72 79 2e 69 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}