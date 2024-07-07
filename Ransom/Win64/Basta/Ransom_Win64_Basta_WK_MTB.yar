
rule Ransom_Win64_Basta_WK_MTB{
	meta:
		description = "Ransom:Win64/Basta.WK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b c8 8b c1 89 44 24 90 01 01 48 8b 44 24 90 01 01 48 8b 8c 24 90 01 04 48 33 c8 48 8b c1 48 89 05 90 01 04 48 8b 44 24 90 01 01 0f be 00 0f be 4c 24 90 01 01 d3 e0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}