
rule Trojan_Win32_TrickBotCrypt_DH_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 03 4d e4 0f b6 11 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 55 e8 8b 45 f0 8b 08 8b 55 f8 8b 02 8b 55 08 0f b6 04 02 03 05 ?? ?? ?? ?? 8b 55 0c 0f b6 0c 0a 33 c8 8b 55 f0 8b 02 8b 55 0c 88 0c 02 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}