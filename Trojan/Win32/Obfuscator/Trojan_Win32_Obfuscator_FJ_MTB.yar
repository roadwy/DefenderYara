
rule Trojan_Win32_Obfuscator_FJ_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.FJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 1c 31 44 24 14 2b 5c 24 14 8b 44 24 3c d1 6c 24 2c 29 44 24 18 ff 4c 24 24 0f 90 01 05 8b 44 24 30 8b 8c 24 90 01 04 5f 5e 89 68 04 5d 89 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}