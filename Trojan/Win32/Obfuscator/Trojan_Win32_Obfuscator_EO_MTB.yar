
rule Trojan_Win32_Obfuscator_EO_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 4d 17 0f b6 03 03 c1 99 8b cf f7 f9 8b 85 90 01 04 83 4d fc ff 8a 8c 15 90 01 04 30 08 40 8d 8d 90 01 04 89 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Obfuscator_EO_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 75 fc 68 90 01 04 a1 90 01 04 50 ff 15 90 01 04 03 f0 68 90 01 04 8b 0d 90 01 04 51 ff 15 90 01 04 03 f0 68 90 01 04 ff 15 90 01 04 03 05 90 01 04 0f be 14 30 f7 da 8b 85 90 01 04 0f be 08 2b ca 8b 95 90 01 04 88 0a 5e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}