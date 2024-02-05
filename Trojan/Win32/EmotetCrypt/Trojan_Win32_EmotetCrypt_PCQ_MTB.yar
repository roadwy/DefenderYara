
rule Trojan_Win32_EmotetCrypt_PCQ_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 32 33 d2 0f b6 c9 03 c1 8b 4d 90 01 01 f7 f7 2b 15 90 01 04 03 55 90 01 01 8a 04 32 8b 55 90 01 01 02 c2 8b 55 90 01 01 32 04 0a 88 01 90 00 } //01 00 
		$a_03_1 = {0f b6 11 8b 45 90 01 01 03 45 e4 0f b6 08 8b 45 1c 0f af 45 1c 03 c8 33 d1 8b 4d 90 01 01 03 4d 90 01 01 88 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}