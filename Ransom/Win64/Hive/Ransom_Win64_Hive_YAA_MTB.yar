
rule Ransom_Win64_Hive_YAA_MTB{
	meta:
		description = "Ransom:Win64/Hive.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 8b 6c 11 08 48 33 6c 08 08 48 89 ac 0c 90 01 04 48 83 c1 08 48 83 f9 28 72 90 00 } //01 00 
		$a_03_1 = {0f 92 c2 c0 e2 90 01 01 08 ca 8a 8c 04 90 01 04 8d 59 90 01 01 80 fb 90 01 01 0f 92 c3 c0 e3 90 01 01 08 cb 48 90 01 02 38 da 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}