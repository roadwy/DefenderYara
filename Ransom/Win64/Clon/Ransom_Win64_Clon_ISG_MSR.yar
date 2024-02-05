
rule Ransom_Win64_Clon_ISG_MSR{
	meta:
		description = "Ransom:Win64/Clon.ISG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {21 00 21 00 21 00 5f 00 52 00 45 00 41 00 44 00 5f 00 21 00 21 00 21 00 2e 00 52 00 54 00 46 00 } //01 00 
		$a_80_1 = {2e 43 49 5f 30 50 } //.CI_0P  01 00 
		$a_00_2 = {57 00 4e 00 45 00 54 00 56 00 69 00 65 00 77 00 } //01 00 
		$a_81_3 = {42 65 69 64 73 6f 33 6a 66 64 73 6a 68 6a 6b 48 55 23 65 32 33 34 32 66 77 72 32 } //00 00 
	condition:
		any of ($a_*)
 
}