
rule Trojan_Win32_EmotetCrypt_PBT_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 29 8a 01 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f3 8a 01 47 41 8a 1c 32 88 04 32 88 59 ff 8b 1d 90 01 04 3b fb 89 54 24 10 72 90 00 } //1
		$a_03_1 = {0f b6 0c 2e 0f b6 c0 03 c1 33 d2 f7 35 90 01 04 8b 44 24 20 8b da 03 d8 ff 15 90 01 04 8a 14 33 8a 44 24 28 8b 4c 24 1c 02 d0 8b 44 24 10 32 14 01 88 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}