
rule Trojan_Win32_SmokeLoader_BJ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d c8 89 45 e0 8d 45 e0 e8 90 02 04 8b 45 e0 33 c7 31 45 f8 89 35 90 02 04 8b 45 f0 89 45 e4 8b 45 f8 29 45 e4 8b 45 e4 89 45 f0 8b 45 c0 29 45 f4 ff 4d d8 0f 90 00 } //02 00 
		$a_01_1 = {81 00 e1 34 ef c6 c3 29 08 c3 01 08 c3 } //00 00 
	condition:
		any of ($a_*)
 
}