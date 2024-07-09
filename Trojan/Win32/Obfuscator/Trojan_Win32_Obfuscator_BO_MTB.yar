
rule Trojan_Win32_Obfuscator_BO_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 c3 8b d8 8d 45 e8 8b d3 e8 ?? ?? ?? ?? 8b 55 e8 8b 45 f4 e8 ?? ?? ?? ?? 8b 45 f4 46 4f 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Obfuscator_BO_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b d1 8d 4c 32 f7 81 c7 ?? ?? ?? ?? 89 7d 00 0f b6 2d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 8b f5 2b f2 81 fe ?? ?? ?? ?? 75 16 8b d1 2b d0 83 ea ?? 83 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}