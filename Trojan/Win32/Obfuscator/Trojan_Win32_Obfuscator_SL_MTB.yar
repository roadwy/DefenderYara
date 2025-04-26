
rule Trojan_Win32_Obfuscator_SL_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f4 c1 e8 05 89 45 f8 8b 45 f8 03 45 c8 89 45 f8 8b 45 fc 33 45 e0 89 45 fc 8b 45 fc 33 45 f8 89 45 fc 83 25 ?? ?? ?? ?? ?? 8b 45 f0 2b 45 fc 89 45 f0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}