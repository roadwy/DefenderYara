
rule Trojan_Win32_Redline_ARD_MTB{
	meta:
		description = "Trojan:Win32/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 44 d8 89 5d ec 8b 45 e8 83 c0 ff 89 45 e8 89 45 b0 8b 4d e4 83 d1 ff 89 4d e4 89 4d b4 8b 55 e0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_ARD_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {53 56 57 c6 45 90 01 01 93 c6 45 90 01 01 f4 c6 45 90 01 01 45 c6 45 90 01 01 a5 c6 45 90 01 01 b5 c6 45 90 01 01 44 c6 45 90 01 01 25 c6 45 90 01 01 73 c6 45 90 01 01 45 c6 45 90 01 01 15 c6 45 90 01 01 a5 c6 45 90 01 01 84 c6 45 90 01 01 64 c6 45 90 01 01 a5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}