
rule Trojan_Win32_TrickBotCrypt_DO_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 08 8b c2 33 d2 8a 14 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a c3 b3 0f f6 2d ?? ?? ?? ?? f6 eb 8a d8 a0 ?? ?? ?? ?? 02 d8 c0 e3 04 8a 04 0a 02 d8 a0 ?? ?? ?? ?? 2a d8 8b 44 24 18 8a 14 28 32 d3 88 14 28 8b 44 24 1c 45 3b e8 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}