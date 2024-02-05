
rule Trojan_Win32_Obfuscator_NV_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 c1 83 e1 90 01 01 8b 54 24 1c 8a 1c 02 2a 1c 0d 90 01 04 80 c3 20 66 c7 44 90 01 04 8b 4c 24 18 88 1c 01 c6 44 24 4b 90 01 01 83 c0 90 01 01 89 44 24 38 8b 74 24 28 39 f0 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}