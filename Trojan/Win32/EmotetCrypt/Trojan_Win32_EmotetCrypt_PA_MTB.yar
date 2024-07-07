
rule Trojan_Win32_EmotetCrypt_PA_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {99 b9 61 03 00 00 f7 f9 8b 0d 90 01 04 bf 61 03 00 00 68 90 01 04 68 90 01 04 0f b6 f2 0f b6 04 0e 03 c5 88 54 24 90 01 01 99 90 00 } //1
		$a_03_1 = {6a 00 50 e8 90 01 04 8b 4c 24 90 01 01 8b 44 24 90 01 01 8b 3d 90 01 04 8b d1 2b 15 90 01 04 83 c1 01 03 c2 0f b6 54 24 90 01 01 8a 14 3a 30 10 3b 4c 24 90 01 01 89 4c 24 90 01 01 0f 8c 90 01 04 8a 4c 24 90 01 01 8b 44 24 90 01 01 8a 54 24 90 01 01 5f 5e 5d 5b 90 00 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}