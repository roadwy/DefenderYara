
rule Trojan_Win32_Obfuscator_BK_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 14 33 c0 8a 44 34 18 81 e1 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 83 c4 04 8a 54 14 14 32 c2 88 03 43 4d 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}