
rule Trojan_Win32_Redline_MKW_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 c7 05 90 01 08 03 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 4c 24 90 01 01 31 4c 24 90 01 01 83 3d 90 01 05 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}