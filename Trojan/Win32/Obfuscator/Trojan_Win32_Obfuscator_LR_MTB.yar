
rule Trojan_Win32_Obfuscator_LR_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 4c 24 0c 05 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 03 fb 8b 4c 24 28 83 44 24 28 04 89 44 24 2c a3 ?? ?? ?? ?? 89 01 0f b7 c7 89 15 ?? ?? ?? ?? 89 7c 24 20 8d 0c 45 ?? ?? ?? ?? 0f af c8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}