
rule Trojan_Win32_Obfuscator_TY_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.TY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 d2 6a 01 5e 81 c6 ?? ?? ?? ?? 87 d6 83 f9 00 ?? ?? 83 7d fc 04 ?? ?? c7 45 fc 00 00 00 00 80 34 01 c4 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}