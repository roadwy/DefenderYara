
rule Trojan_Win32_Obfuscator_KP_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.KP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 f8 8b 44 24 18 8b d7 8b 7c 24 20 2b d6 83 44 24 20 04 83 c2 ?? 05 ?? ?? ?? ?? 89 44 24 18 89 07 8d ba ?? ?? ?? ?? a3 ?? ?? ?? ?? 03 f9 ff 4c 24 14 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}