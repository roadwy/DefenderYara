
rule Trojan_Win32_Obfuscator_TR_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.TR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 00 23 45 c8 8b 4d c8 83 c1 01 99 f7 f9 8b 55 a0 2b d0 89 55 a0 8b 45 d8 8b 4d 08 8b 55 c4 89 14 81 e9 58 fe ff ff ?? ?? 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}