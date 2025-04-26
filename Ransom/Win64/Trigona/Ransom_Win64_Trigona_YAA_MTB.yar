
rule Ransom_Win64_Trigona_YAA_MTB{
	meta:
		description = "Ransom:Win64/Trigona.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 45 30 48 2b 45 38 48 89 45 38 48 0f b6 45 38 88 45 2f 48 0f b6 45 2f 30 03 83 ee 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}