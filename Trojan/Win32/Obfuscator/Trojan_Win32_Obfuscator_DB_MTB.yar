
rule Trojan_Win32_Obfuscator_DB_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 8b d7 d3 e2 8b 4d f0 8b c7 c1 e8 05 03 55 e4 03 45 e0 03 cf 33 d0 33 d1 8b 0d ?? ?? ?? ?? 29 55 f8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Obfuscator_DB_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.DB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 78 40 89 45 f8 b2 10 8d 73 10 89 4d f4 2b fb 8a 44 37 ff 8d 76 ff 8d 49 ff 88 41 f0 30 06 0f b6 41 40 88 01 80 c2 ff 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}