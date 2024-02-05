
rule Ransom_Win64_Basta_GG_MTB{
	meta:
		description = "Ransom:Win64/Basta.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 09 33 c1 88 05 90 01 04 0f be 44 24 90 01 01 0f be 0d 90 01 04 d3 e0 88 84 24 90 01 04 48 8b 84 24 90 01 04 0f be 00 48 8b 8c 24 90 01 04 0f be 09 0b c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}