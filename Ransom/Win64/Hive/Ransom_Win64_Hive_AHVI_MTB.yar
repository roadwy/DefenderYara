
rule Ransom_Win64_Hive_AHVI_MTB{
	meta:
		description = "Ransom:Win64/Hive.AHVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 d0 4d 29 d0 4d 89 c1 49 f7 d8 49 c1 f8 3f 4d 21 d0 4c 8b 5c 24 48 4b 8d 3c 03 4c 8b 64 24 38 66 ?? 49 39 cc 72 74 48 89 44 24 30 4d 29 d4 49 8d 51 e0 49 89 d2 48 f7 da 48 c1 fa 3f 48 21 d1 4a 8d 04 19 49 8d 5c 24 e0 4c 89 d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}