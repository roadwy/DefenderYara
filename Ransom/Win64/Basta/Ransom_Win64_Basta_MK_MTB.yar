
rule Ransom_Win64_Basta_MK_MTB{
	meta:
		description = "Ransom:Win64/Basta.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 8b 10 40 8a c7 40 8a cf 81 c7 90 01 04 c1 c7 90 01 01 41 02 04 11 d2 c0 41 88 04 11 49 ff c1 48 83 ee 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}