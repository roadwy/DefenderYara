
rule Ransom_Win64_BlackByte_DKC_MTB{
	meta:
		description = "Ransom:Win64/BlackByte.DKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 98 df 00 00 44 8b 90 02 06 83 ee 20 90 01 01 8b f8 e8 90 00 } //01 00 
		$a_01_1 = {32 4c 24 04 41 32 ca 40 32 ce 41 32 cf 44 32 6c 24 08 88 4d 00 44 32 eb 44 32 ee 45 32 ef 44 88 6d 01 48 83 c5 04 48 83 6c 24 20 01 48 89 6c 24 18 0f 85 } //01 00 
		$a_03_2 = {0f b6 04 1f 30 03 48 ff c3 48 83 e9 01 75 f1 48 83 ef 10 0f 29 90 01 02 48 83 ee 01 75 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}