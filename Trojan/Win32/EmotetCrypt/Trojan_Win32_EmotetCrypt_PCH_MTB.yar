
rule Trojan_Win32_EmotetCrypt_PCH_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 14 0e 0f b6 c0 03 c2 33 d2 f7 f5 0f b6 04 0a 8b 54 24 14 32 44 1a ff 83 6c 24 20 01 88 43 ff } //1
		$a_03_1 = {0f b6 14 33 0f b6 c0 03 c2 33 d2 f7 35 90 01 04 89 54 24 14 ff 15 90 01 04 8b 44 24 10 8a 0c 28 8b 54 24 14 32 0c 32 8b 44 24 20 88 4d 00 90 00 } //1
		$a_03_2 = {0f b6 12 0f b6 c0 03 c2 33 d2 f7 f1 8b da ff 15 90 01 04 8b 45 f4 8a 04 38 32 04 33 88 07 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}