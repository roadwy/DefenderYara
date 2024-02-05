
rule Ransom_Win32_Genasom_DA_MTB{
	meta:
		description = "Ransom:Win32/Genasom.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 4e 43 52 59 50 54 45 44 20 42 59 20 54 48 45 20 57 49 4e 54 45 4e 5a 5a 20 53 45 43 55 52 49 54 59 20 54 4f 4f 4c } //01 00 
		$a_01_1 = {44 45 43 52 59 50 54 20 46 49 4c 45 53 20 48 45 52 45 } //01 00 
		$a_81_2 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //01 00 
		$a_81_3 = {42 69 74 63 6f 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}