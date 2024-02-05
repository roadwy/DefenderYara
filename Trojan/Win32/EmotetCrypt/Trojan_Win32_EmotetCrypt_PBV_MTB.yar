
rule Trojan_Win32_EmotetCrypt_PBV_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f b6 14 1a 8a 03 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f1 8a 03 83 c3 01 83 6c 24 14 01 8b fa 8a 14 37 88 04 37 88 53 ff 89 7c 24 10 75 } //01 00 
		$a_03_1 = {0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 8b da 03 5c 24 20 ff 15 90 01 04 8a 0c 33 8b 44 24 14 02 4c 24 28 8b 54 24 1c 32 0c 02 83 c0 01 83 6c 24 10 01 88 48 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}