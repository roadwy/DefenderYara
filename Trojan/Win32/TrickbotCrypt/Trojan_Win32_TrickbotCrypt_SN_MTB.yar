
rule Trojan_Win32_TrickbotCrypt_SN_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 04 a3 90 01 04 33 d2 33 c0 8b 0d 90 01 04 88 04 01 40 3d 90 01 04 7c 90 00 } //01 00 
		$a_03_1 = {0f b6 04 0e 0f b6 da 8b 54 24 90 01 01 0f b6 14 13 03 d7 03 c2 99 bf 90 01 02 00 00 f7 ff 8a 04 0e 83 c1 02 0f b6 fa 8a 14 37 88 54 0e 90 01 01 88 04 37 8d 2c 37 8d 43 01 99 f7 7c 24 90 01 01 8b 35 90 01 04 8b 44 24 90 01 01 0f b6 da 0f b6 14 03 0f b6 44 0e 90 01 01 03 d7 03 c2 99 bf 90 01 02 00 00 f7 ff 8a 44 0e 90 01 01 0f b6 fa 8a 14 37 8d 2c 37 88 54 0e 90 01 01 88 45 00 8d 43 90 01 01 99 f7 7c 24 18 81 f9 90 01 02 00 00 0f 8c 90 00 } //01 00 
		$a_03_2 = {0f b6 54 24 90 01 01 a1 90 01 04 8a 0c 02 8b 44 24 90 01 01 30 0c 03 8b 44 24 90 01 01 43 3b d8 0f 8c 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}