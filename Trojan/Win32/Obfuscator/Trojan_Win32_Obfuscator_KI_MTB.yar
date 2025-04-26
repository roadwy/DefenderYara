
rule Trojan_Win32_Obfuscator_KI_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.KI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c9 31 d2 [0-30] c7 45 fc ?? ?? ?? ?? 80 34 01 ?? 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc 05 ?? ?? ?? ?? ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}