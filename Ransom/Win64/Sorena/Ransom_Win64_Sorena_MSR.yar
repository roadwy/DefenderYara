
rule Ransom_Win64_Sorena_MSR{
	meta:
		description = "Ransom:Win64/Sorena!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 20 2d 49 6e 66 2e 62 61 74 2e 63 6d 64 2e 63 6f 6d 2e 65 78 65 33 31 32 35 } //01 00 
		$a_01_1 = {45 6e 63 72 79 70 74 2e 65 78 65 62 61 64 } //01 00 
		$a_01_2 = {6d 61 69 6e 2e 64 65 72 69 76 65 4b 65 79 } //01 00 
		$a_01_3 = {73 6f 72 65 6e 61 20 56 69 72 75 73 } //00 00 
	condition:
		any of ($a_*)
 
}