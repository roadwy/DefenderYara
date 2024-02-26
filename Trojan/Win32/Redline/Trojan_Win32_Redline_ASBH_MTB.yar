
rule Trojan_Win32_Redline_ASBH_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 c1 e0 04 89 45 fc 8b 45 e0 01 45 fc 8b 45 f4 8b 4d f8 8d 14 03 31 55 fc d3 e8 03 45 e4 81 3d 90 02 04 21 01 00 00 8b f8 75 90 00 } //01 00 
		$a_01_1 = {76 65 70 69 74 65 72 6f 74 61 74 61 63 65 72 65 77 65 72 65 63 65 62 65 74 69 77 } //00 00  vepiterotatacerewerecebetiw
	condition:
		any of ($a_*)
 
}