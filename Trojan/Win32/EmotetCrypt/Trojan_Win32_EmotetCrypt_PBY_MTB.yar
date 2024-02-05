
rule Trojan_Win32_EmotetCrypt_PBY_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 12 0f b6 c0 03 c2 33 d2 f7 f1 89 55 ec ff 15 90 01 04 8b 45 f4 8a 04 38 8b 4d ec 32 04 31 88 07 90 00 } //01 00 
		$a_03_1 = {0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 89 54 24 1c ff 15 90 01 04 8b 44 24 18 8a 0c 18 8b 54 24 14 32 0c 32 83 c3 01 83 6c 24 24 01 88 4b ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}