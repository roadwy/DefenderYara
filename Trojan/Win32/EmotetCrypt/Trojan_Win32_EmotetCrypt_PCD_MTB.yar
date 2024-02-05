
rule Trojan_Win32_EmotetCrypt_PCD_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 33 81 e2 ff 00 00 00 03 c2 33 d2 f7 35 90 01 04 89 54 24 34 ff 15 90 01 04 8b 44 24 24 8b 54 24 2c 8a 0c 28 8a 04 32 32 c8 8b 44 24 20 88 4d 00 90 00 } //01 00 
		$a_03_1 = {0f b6 0c 1a 33 d2 03 c1 f7 f7 8b f2 ff 15 90 01 04 8b 4d 18 8b 55 08 0f b6 04 0a 32 04 1e 88 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}