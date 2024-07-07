
rule Trojan_Win32_EmotetCrypt_D_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {59 8b d8 8b 0d 90 01 04 33 d2 8b c1 f7 f3 03 55 18 8a 04 32 8b 55 0c 32 04 0a 8b 55 10 88 04 0a ff 05 90 01 04 39 3d 90 01 04 75 cb 90 00 } //1
		$a_01_1 = {8b 45 08 03 45 fc 8a 08 32 ca 8b 55 08 03 55 fc 88 0a 8b 45 f8 83 c0 01 89 45 f8 8b 45 fc 99 b9 05 00 00 00 f7 f9 85 d2 75 07 c7 45 f8 00 00 00 00 eb a8 8b e5 5d c3 } //1
		$a_01_2 = {0f b6 14 0f 88 14 0e 88 04 0f 0f b6 14 0f 0f b6 04 0e 03 c2 99 f7 fb 0f b6 c2 0f b6 14 08 30 55 ff 83 6c 24 14 01 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}