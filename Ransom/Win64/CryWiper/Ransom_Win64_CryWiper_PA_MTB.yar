
rule Ransom_Win64_CryWiper_PA_MTB{
	meta:
		description = "Ransom:Win64/CryWiper.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 43 52 59 } //01 00 
		$a_01_1 = {52 45 41 44 4d 45 2e 74 78 74 } //01 00 
		$a_01_2 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_01_3 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 66 6f 72 3d 63 3a 20 2f 61 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}