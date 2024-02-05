
rule Trojan_Win32_VBkrypt_GC_MTB{
	meta:
		description = "Trojan:Win32/VBkrypt.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 00 a0 00 00 90 02 1e ff d0 90 02 19 8b 1c 0f 90 02 07 31 f3 90 02 08 89 1c 08 90 02 08 83 e9 04 90 02 0a 7d 90 00 } //01 00 
		$a_02_1 = {68 00 b0 00 00 90 02 1e ff d0 90 02 19 8b 1c 0f 90 02 07 31 f3 90 02 08 89 1c 08 90 02 08 83 e9 04 90 02 0a 7d 90 00 } //01 00 
		$a_02_2 = {0f 77 89 1c 08 90 02 08 83 e9 04 90 02 0a 7d 90 02 0a ff e0 90 0a 46 00 ff d0 90 02 19 8b 1c 0f 90 02 07 31 f3 90 00 } //01 00 
		$a_02_3 = {89 1c 08 0f 77 90 02 08 83 e9 04 90 02 0a 7d 90 02 0a ff e0 90 0a 46 00 ff d0 90 02 19 8b 1c 0f 90 02 07 31 f3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}