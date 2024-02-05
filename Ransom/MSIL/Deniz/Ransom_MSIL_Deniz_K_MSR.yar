
rule Ransom_MSIL_Deniz_K_MSR{
	meta:
		description = "Ransom:MSIL/Deniz.K!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {44 00 65 00 6e 00 69 00 7a 00 5f 00 4b 00 69 00 7a 00 69 00 2e 00 4e 00 45 00 54 00 } //02 00 
		$a_00_1 = {52 00 65 00 61 00 64 00 4d 00 45 00 } //01 00 
		$a_02_2 = {65 00 76 00 62 00 90 02 05 74 00 6d 00 70 00 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 } //e2 13 
	condition:
		any of ($a_*)
 
}