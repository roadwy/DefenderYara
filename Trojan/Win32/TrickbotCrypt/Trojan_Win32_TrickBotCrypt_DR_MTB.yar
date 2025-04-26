
rule Trojan_Win32_TrickBotCrypt_DR_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 32 33 d2 8a 14 37 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a c3 b3 1f f6 2d ?? ?? ?? ?? f6 eb 8a 14 32 2a d0 a0 ?? ?? ?? ?? f6 eb 02 d0 a0 ?? ?? ?? ?? 2a d0 8b 44 24 ?? 8a 1c 01 32 da 88 1c 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}