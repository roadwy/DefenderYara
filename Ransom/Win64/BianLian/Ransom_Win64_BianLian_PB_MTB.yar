
rule Ransom_Win64_BianLian_PB_MTB{
	meta:
		description = "Ransom:Win64/BianLian.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //0a 00  Go build ID:
		$a_03_2 = {48 8b 54 24 90 01 01 48 8d 4a 90 01 01 48 8b 84 24 90 02 04 48 8b 54 24 90 01 01 48 39 ca 0f 8e 90 02 04 48 89 4c 24 90 01 01 48 8b b4 24 90 02 04 48 89 f7 48 0f af f1 48 03 35 90 01 04 48 89 b4 24 90 02 04 48 89 c3 48 8b 84 24 90 02 04 48 89 f9 e8 90 02 04 48 8b b4 24 90 02 04 48 39 f0 75 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 f4 67 05 80 5c 32 00 00 f5 67 05 80 00 00 01 00 } //32 00 
	condition:
		any of ($a_*)
 
}