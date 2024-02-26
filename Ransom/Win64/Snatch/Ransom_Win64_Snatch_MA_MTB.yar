
rule Ransom_Win64_Snatch_MA_MTB{
	meta:
		description = "Ransom:Win64/Snatch.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 6b c9 03 48 8b 15 90 01 04 89 84 0a f4 00 00 00 48 63 44 24 48 48 8b 8c 24 c8 00 00 00 48 8b 89 80 00 00 00 8b 04 81 89 44 24 3c 8b 44 24 3c 0f af 05 90 01 04 89 44 24 3c 8b 44 24 3c c1 e8 10 48 8b 8c 24 c8 00 00 00 48 63 49 50 48 8b 15 90 01 04 48 8b 92 98 00 00 00 88 04 0a 90 00 } //05 00 
		$a_03_1 = {c1 e8 08 48 8b 0d 90 01 04 48 63 49 50 48 8b 15 90 01 04 48 8b 92 98 00 00 00 88 04 0a 48 8b 05 90 01 04 8b 40 50 ff c0 48 8b 0d 90 01 04 89 41 50 48 8b 05 90 01 04 8b 40 2c 83 f0 0a 48 8b 0d 90 01 04 8b 89 b0 00 00 00 0b c8 8b c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}