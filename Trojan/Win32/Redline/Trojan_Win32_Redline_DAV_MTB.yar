
rule Trojan_Win32_Redline_DAV_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 83 44 24 14 64 29 44 24 14 83 6c 24 14 64 8b 44 24 14 8d 4c 24 10 e8 90 02 04 8b 44 24 28 01 44 24 10 8b 44 24 14 8b 4c 24 18 8d 14 06 31 54 24 10 d3 e8 03 c3 81 3d 90 02 04 21 01 00 00 8b f0 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}