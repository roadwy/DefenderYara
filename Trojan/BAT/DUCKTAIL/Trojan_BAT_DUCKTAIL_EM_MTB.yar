
rule Trojan_BAT_DUCKTAIL_EM_MTB{
	meta:
		description = "Trojan:BAT/DUCKTAIL.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 55 43 49 54 41 2e 48 65 6c 70 65 72 73 } //01 00  DUCITA.Helpers
		$a_81_1 = {53 44 43 42 75 6e 64 6c 65 2e 48 65 6c 70 65 72 73 } //01 00  SDCBundle.Helpers
		$a_81_2 = {67 65 74 5f 63 30 33 70 31 5f 32 } //01 00  get_c03p1_2
		$a_81_3 = {54 4c 2b 65 68 38 4f 57 67 56 4a 74 4d 2f 72 77 70 74 42 56 31 52 67 39 65 6a 2f 4d 6e 44 70 78 59 2b 4d 68 73 47 67 4f 38 68 4d 3d } //01 00  TL+eh8OWgVJtM/rwptBV1Rg9ej/MnDpxY+MhsGgO8hM=
		$a_81_4 = {74 6b 66 67 6b 34 33 35 6a 6b 64 67 66 2e 64 6c 6c } //00 00  tkfgk435jkdgf.dll
	condition:
		any of ($a_*)
 
}