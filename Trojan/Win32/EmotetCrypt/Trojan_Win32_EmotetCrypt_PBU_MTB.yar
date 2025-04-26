
rule Trojan_Win32_EmotetCrypt_PBU_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 45 f0 0f b6 14 38 8a 1f 03 55 fc 0f b6 c3 03 c2 33 d2 f7 f1 8d 04 32 89 55 fc 8a 10 88 18 88 17 47 ff 4d f4 75 } //1
		$a_03_1 = {0f b6 14 32 0f b6 c0 03 c2 33 d2 f7 f1 8b da 03 5d f0 ff 15 ?? ?? ?? ?? 8a 04 33 02 45 0f 8b 4d ec 32 04 39 88 07 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}