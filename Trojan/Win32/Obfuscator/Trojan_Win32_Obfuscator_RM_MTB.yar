
rule Trojan_Win32_Obfuscator_RM_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 89 0d 90 01 04 8b c2 33 05 90 01 04 c7 05 90 01 04 00 00 00 00 8b d0 01 15 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 8b e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Obfuscator_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b df 3b fe 73 90 01 01 68 90 01 04 e8 90 01 04 8b 4c 24 90 01 01 8b 54 24 90 01 01 8a c3 2a 44 24 90 01 01 83 c4 04 32 03 51 32 44 24 90 01 01 52 88 03 ff 15 90 01 04 03 5c 24 90 01 01 3b de 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}