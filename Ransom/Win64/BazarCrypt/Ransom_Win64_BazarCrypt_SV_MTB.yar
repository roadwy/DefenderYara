
rule Ransom_Win64_BazarCrypt_SV_MTB{
	meta:
		description = "Ransom:Win64/BazarCrypt.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {45 33 c9 45 8b c4 33 d2 48 8b 90 01 03 00 00 00 ff 15 90 01 04 85 c0 0f 84 90 01 02 ff ff ff d3 b9 00 0c 00 00 ff 15 90 00 } //02 00 
		$a_03_1 = {ba 61 1e 00 00 41 b8 14 00 00 00 4c 8d 25 90 01 04 49 8b cc ff d3 48 8b d8 48 8b d0 49 8b cc ff d7 48 8b f8 48 8b d3 49 8b cc ff 15 90 00 } //02 00 
		$a_03_2 = {ba 01 68 00 00 48 90 01 04 ff 15 90 01 04 85 c0 0f 84 90 01 02 ff ff 48 8d 0d 97 d7 01 00 e8 90 01 02 00 00 44 8b c8 8b 54 90 01 02 33 c9 41 b8 00 10 00 00 ff 15 90 01 04 48 8b d8 44 8b 90 01 03 48 8b d7 48 8b c8 e8 ca 25 00 00 44 8b 90 01 03 44 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}