
rule Trojan_Win32_Obfuscator_ZP_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.ZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 81 e9 ?? ?? ?? ?? 89 4d fc c1 45 08 04 8b 55 fc 81 c2 ?? ?? ?? ?? 89 55 fc 8b 45 08 05 ?? ?? ?? ?? 89 45 08 8b 45 08 8b e5 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}