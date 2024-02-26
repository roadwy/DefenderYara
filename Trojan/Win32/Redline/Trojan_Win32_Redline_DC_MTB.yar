
rule Trojan_Win32_Redline_DC_MTB{
	meta:
		description = "Trojan:Win32/Redline.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d7 80 b6 00 c0 90 01 03 6a 00 ff d7 80 86 00 c0 90 01 03 6a 00 ff d7 80 86 00 c0 90 01 03 6a 00 ff d7 80 b6 00 c0 90 01 03 6a 00 ff d7 80 86 00 c0 90 01 03 6a 00 ff d7 80 86 00 c0 90 01 03 6a 00 ff d7 80 86 00 c0 90 01 03 6a 00 ff d7 80 86 00 c0 90 01 03 6a 00 ff d7 80 b6 00 c0 90 01 03 46 81 fe 90 01 04 72 94 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}