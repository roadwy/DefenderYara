
rule Trojan_Win32_LokibotCrypt_RK_MTB{
	meta:
		description = "Trojan:Win32/LokibotCrypt.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 0b 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 6a 01 ff d6 b8 00 00 00 00 f7 f0 90 02 1f 6a 00 6a 00 e8 90 02 04 89 f6 90 02 1f 8b c7 90 02 1f 5f 5e 5b c3 90 00 } //01 00 
		$a_01_1 = {b8 00 00 00 00 f7 f0 83 e8 00 83 e8 00 83 e8 00 83 e8 00 83 e8 00 6a 00 6a 00 e8 } //01 00 
		$a_03_2 = {8a 45 fa 32 45 f9 88 01 83 e8 00 90 02 1f 8a 55 fb 8b c1 90 02 0a 83 e8 00 90 02 0a 90 02 1f 88 01 90 00 } //01 00 
		$a_03_3 = {8a 10 32 55 fb 88 11 90 02 1f 8a 55 fa 30 11 90 02 1f 47 40 4e 75 90 00 } //01 00 
		$a_03_4 = {00 b8 00 00 00 00 f7 f0 89 f6 90 02 1f 8b c6 5e 5b 5d c3 90 00 } //01 00 
		$a_03_5 = {32 55 fb 88 11 90 02 1f 8a 55 fa 30 11 90 0a 3f 00 8a 10 90 00 } //01 00 
		$a_03_6 = {b8 00 00 00 00 f7 f0 83 e8 00 90 02 1f 6a 00 6a 00 6a 00 e8 90 02 1f 8b c6 5e 5b 5d c3 90 00 } //01 00 
		$a_03_7 = {b8 00 00 00 00 f7 f0 8b c6 5e 5b 5d c3 90 0a 2f 00 68 90 01 03 00 6a 01 90 03 01 02 e8 ff 15 90 00 } //01 00 
		$a_03_8 = {b8 00 00 00 00 f7 f0 8b c6 5e 5b c3 90 0a 2f 00 68 90 01 03 00 6a 01 ff 15 90 00 } //01 00 
		$a_03_9 = {03 f3 8a 01 88 45 90 01 01 8b c3 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 90 01 01 8a 45 90 01 01 32 45 90 01 01 88 06 8a 45 90 01 01 30 06 eb 90 01 01 8a 45 90 01 01 88 06 43 41 4f 75 90 00 } //01 00 
		$a_03_10 = {8a 45 f6 32 45 f5 88 01 83 e8 00 8a 55 f7 8b c1 e8 90 02 1f 88 01 90 02 1f 46 43 4f 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}