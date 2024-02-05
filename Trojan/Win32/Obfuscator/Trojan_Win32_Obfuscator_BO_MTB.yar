
rule Trojan_Win32_Obfuscator_BO_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 c3 8b d8 8d 45 e8 8b d3 e8 90 01 04 8b 55 e8 8b 45 f4 e8 90 01 04 8b 45 f4 46 4f 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Obfuscator_BO_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b d1 8d 4c 32 f7 81 c7 90 01 04 89 7d 00 0f b6 2d 90 01 04 0f b6 15 90 01 04 8b f5 2b f2 81 fe 90 01 04 75 16 8b d1 2b d0 83 ea 90 01 01 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}