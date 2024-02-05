
rule Trojan_Win32_CryptInjector_F_MTB{
	meta:
		description = "Trojan:Win32/CryptInjector.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {85 c0 76 20 8b c8 83 e1 90 01 01 85 c9 75 0e 8a 0a 80 f1 90 01 01 8b 5d fc 03 d8 88 0b eb 09 8b 4d fc 03 c8 8a 1a 88 19 40 42 3d 90 01 04 75 d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}