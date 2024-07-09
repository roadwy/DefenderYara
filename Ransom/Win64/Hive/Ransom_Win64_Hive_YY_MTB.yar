
rule Ransom_Win64_Hive_YY_MTB{
	meta:
		description = "Ransom:Win64/Hive.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8a 04 13 48 8b 94 24 ?? 00 00 00 32 04 0a 48 8b 4c 24 ?? 30 04 29 48 ff c5 49 39 ef 48 8b 9c 24 d8 00 00 00 90 13 49 39 ec 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}