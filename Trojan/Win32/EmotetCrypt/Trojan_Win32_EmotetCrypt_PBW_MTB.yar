
rule Trojan_Win32_EmotetCrypt_PBW_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 01 8b 55 f4 03 55 f0 0f b6 0a 03 c1 33 d2 f7 35 ?? ?? ?? ?? 8b 45 1c 0f af 45 1c 03 d0 89 55 e4 8b 4d 08 03 4d ec 0f b6 11 8b 45 f4 03 45 e4 0f b6 08 8b 45 1c 0f af 45 1c 03 c8 33 d1 8b 4d 18 03 4d ec 88 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}