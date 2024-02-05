
rule Ransom_Win32_PhobosCrypt_SK_MTB{
	meta:
		description = "Ransom:Win32/PhobosCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {55 29 2c e4 89 04 e4 ff 93 90 01 04 52 33 14 e4 09 c2 83 e7 00 31 d7 5a 89 4d f8 31 c9 31 f9 89 8b 90 01 04 8b 4d f8 83 fb 00 76 90 00 } //02 00 
		$a_02_1 = {f3 a4 56 c7 04 e4 ff ff 0f 00 59 89 7d f8 29 ff 0b bb 90 01 04 89 f8 8b 7d f8 55 81 04 e4 90 01 04 29 2c e4 8f 83 90 01 04 21 8b 90 01 04 89 4d f8 8b 8b 90 01 04 01 c1 51 8b 4d f8 58 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}