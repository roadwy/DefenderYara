
rule Trojan_Win32_Redline_GNH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 35 90 01 04 8b 4d 08 03 4d fc 88 01 6a 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNH_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 69 db 90 01 04 69 0c b8 90 01 04 47 8b c1 c1 e8 18 33 c1 69 c8 90 01 04 33 d9 3b fd 0f 8c 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNH_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 33 d3 ee 8b 4c 24 90 01 01 89 44 24 90 01 01 8d 44 24 90 01 01 89 74 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}