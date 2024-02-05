
rule Trojan_Win32_Obfuscator_GF_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {75 14 c7 05 90 01 08 c7 05 90 01 08 8b c5 33 ca c1 e8 05 03 44 24 24 89 44 24 14 89 4c 24 10 8b 44 24 14 31 44 24 10 2b 7c 24 10 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}