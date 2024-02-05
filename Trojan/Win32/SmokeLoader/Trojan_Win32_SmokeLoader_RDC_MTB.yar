
rule Trojan_Win32_SmokeLoader_RDC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b c6 d3 e8 03 45 cc 89 45 f8 33 45 e8 31 45 fc 2b 5d fc ff 4d dc 89 5d e0 } //02 00 
		$a_03_1 = {8a 84 30 3b 2d 0b 00 8b 0d 90 01 04 88 04 31 81 3d 90 01 04 92 02 00 00 75 08 57 57 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}