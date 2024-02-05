
rule Trojan_Win32_Obfuscator_XD_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.XD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 8b cf c1 e1 04 03 4c 24 28 8b c7 c1 e8 05 03 44 24 30 03 d7 33 ca 81 3d 90 01 08 c7 05 90 01 08 89 1d 90 01 04 89 1d 90 01 04 89 4c 24 0c 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}