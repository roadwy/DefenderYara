
rule Trojan_Win32_SmokeLoader_XAA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.XAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 44 24 90 01 01 03 de 33 d8 8b 44 24 90 01 01 68 90 01 04 33 c3 8d 54 24 90 01 01 52 c7 05 90 01 08 c7 05 90 01 08 2b f8 e8 90 01 04 4d 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}