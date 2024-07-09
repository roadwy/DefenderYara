
rule Trojan_Win32_Obfuscator_NV_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c1 83 e1 ?? 8b 54 24 1c 8a 1c 02 2a 1c 0d ?? ?? ?? ?? 80 c3 20 66 c7 44 ?? ?? ?? ?? 8b 4c 24 18 88 1c 01 c6 44 24 4b ?? 83 c0 ?? 89 44 24 38 8b 74 24 28 39 f0 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}