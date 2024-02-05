
rule Trojan_Win32_Redline_CAU_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 44 24 18 89 44 24 24 8b 44 24 2c 01 44 24 24 8b 4c 24 20 8b 54 24 18 d3 ea 8b 4c 24 3c 8d 44 24 30 c7 05 90 02 04 ee 3d ea f4 89 54 24 30 e8 90 02 04 8b 44 24 24 31 44 24 14 81 3d 90 02 04 e6 09 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}