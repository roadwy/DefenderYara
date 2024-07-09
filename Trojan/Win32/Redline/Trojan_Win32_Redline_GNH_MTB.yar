
rule Trojan_Win32_Redline_GNH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 35 ?? ?? ?? ?? 8b 4d 08 03 4d fc 88 01 6a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNH_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 69 db ?? ?? ?? ?? 69 0c b8 ?? ?? ?? ?? 47 8b c1 c1 e8 18 33 c1 69 c8 ?? ?? ?? ?? 33 d9 3b fd 0f 8c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNH_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 33 d3 ee 8b 4c 24 ?? 89 44 24 ?? 8d 44 24 ?? 89 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}