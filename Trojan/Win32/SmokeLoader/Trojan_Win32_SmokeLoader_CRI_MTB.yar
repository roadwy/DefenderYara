
rule Trojan_Win32_SmokeLoader_CRI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 ee 8b 4d d0 03 c1 33 c2 03 75 d8 81 3d 90 01 04 21 01 00 00 89 45 fc 75 18 53 ff 15 90 01 04 68 a0 2e 40 00 53 53 53 ff 15 90 01 04 8b 45 fc 33 c6 29 45 f0 89 45 fc 8d 45 f4 e8 90 01 04 ff 4d e4 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}