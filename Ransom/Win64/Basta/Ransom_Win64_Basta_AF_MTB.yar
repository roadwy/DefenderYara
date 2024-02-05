
rule Ransom_Win64_Basta_AF_MTB{
	meta:
		description = "Ransom:Win64/Basta.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f af c0 89 43 90 01 01 8b 43 90 01 01 35 90 01 04 01 43 90 01 01 8b 83 90 01 04 83 e8 90 01 01 01 83 90 01 04 48 8b 83 90 01 04 44 88 04 01 b8 90 01 04 ff 83 90 01 04 8b 4b 90 01 01 2b c1 01 43 90 01 01 8d 81 90 01 04 01 83 90 01 04 49 81 f9 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}