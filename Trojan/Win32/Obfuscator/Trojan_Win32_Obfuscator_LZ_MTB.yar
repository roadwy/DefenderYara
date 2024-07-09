
rule Trojan_Win32_Obfuscator_LZ_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.LZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c3 83 ea ?? a3 ?? ?? ?? ?? 8b 44 24 10 8b 4c 24 24 83 44 24 10 04 81 c1 ?? ?? ?? ?? 89 08 8b c6 2b c2 69 f8 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 03 fa } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}