
rule Trojan_Win32_Redline_IA_MTB{
	meta:
		description = "Trojan:Win32/Redline.IA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 54 24 3c 01 54 24 14 c7 05 90 01 04 ee 3d ea f4 8b 44 24 2c 31 44 24 10 8b 44 24 10 31 44 24 14 83 3d 90 00 } //0a 00 
		$a_03_1 = {56 69 72 74 c7 05 90 01 04 75 61 6c 50 c7 05 90 01 04 72 6f 74 65 c6 05 90 01 04 63 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}