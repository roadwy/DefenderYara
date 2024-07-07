
rule Trojan_Win32_Redline_ABH_MTB{
	meta:
		description = "Trojan:Win32/Redline.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ee 8b 4c 24 28 89 44 24 2c 8d 44 24 18 89 74 24 18 c7 05 90 01 04 ee 3d ea f4 e8 e4 fe ff ff 8b 44 24 2c 31 44 24 14 81 3d 90 01 04 e6 09 00 00 75 0c 6a 00 6a 00 6a 00 ff 15 90 01 04 8b 4c 24 14 31 4c 24 18 81 3d 90 01 04 13 02 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}