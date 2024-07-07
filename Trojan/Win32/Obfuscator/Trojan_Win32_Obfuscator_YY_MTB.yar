
rule Trojan_Win32_Obfuscator_YY_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f0 03 75 fc 68 90 01 04 ff 15 90 01 04 03 f0 68 90 01 04 ff 15 90 01 04 03 f0 8b 4d 08 03 31 8b 55 08 89 32 5e 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Obfuscator_YY_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c1 8d 88 90 01 04 83 44 24 10 04 81 c3 90 01 04 69 c1 90 01 04 89 1e 8b f2 2b f0 2b 74 24 14 8d 4e 08 2b 0d 90 01 04 83 e9 90 01 01 83 6c 24 18 90 01 01 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}