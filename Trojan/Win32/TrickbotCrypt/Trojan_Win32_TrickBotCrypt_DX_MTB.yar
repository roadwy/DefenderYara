
rule Trojan_Win32_TrickBotCrypt_DX_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 f8 8a c1 f6 eb b1 1f f6 e9 8a 0c 32 b2 1f 2a c8 a0 ?? ?? ?? ?? f6 ea 02 c8 2a 0d ?? ?? ?? ?? 30 0f 90 09 06 00 8b 45 ?? 8b 7d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}