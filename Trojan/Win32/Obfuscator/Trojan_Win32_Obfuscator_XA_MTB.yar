
rule Trojan_Win32_Obfuscator_XA_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.XA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 10 8b cb c1 e1 04 8b f3 03 4c 24 2c 03 c3 c1 ee 05 33 c8 03 74 24 30 90 02 03 81 3d 90 01 08 c7 05 90 01 08 90 02 10 89 4c 24 0c 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}