
rule Trojan_Win32_Obfuscator_FT_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 0a 80 f1 e7 8b 5d fc 03 d8 88 0b ?? ?? 8b 4d fc 03 c8 8a 1a 88 19 [0-30] 8b 45 fc 05 ?? ?? ?? ?? ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}