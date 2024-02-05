
rule Ransom_Win64_Basta_ML_MTB{
	meta:
		description = "Ransom:Win64/Basta.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 8b 10 40 8a cf 41 8a 04 12 d2 c8 40 02 c7 69 ff 90 01 04 41 88 04 12 49 ff c2 c1 cf 0d 48 83 ee 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}