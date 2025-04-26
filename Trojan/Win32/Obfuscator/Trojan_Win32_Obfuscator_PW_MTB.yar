
rule Trojan_Win32_Obfuscator_PW_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ff 8a 81 ?? ?? ?? ?? 30 04 3a 83 f9 ?? ?? ?? 33 c9 ?? ?? 41 42 3b d3 ?? ?? 8b 85 ?? ?? ?? ?? ff d0 6a ?? ff } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}