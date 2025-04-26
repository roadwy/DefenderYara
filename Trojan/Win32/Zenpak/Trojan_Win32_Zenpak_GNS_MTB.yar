
rule Trojan_Win32_Zenpak_GNS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 40 8d 05 ?? ?? ?? ?? 89 18 83 c2 ?? 31 c2 4a 31 2d ?? ?? ?? ?? 29 d0 31 d0 89 f0 50 8f 05 ?? ?? ?? ?? 31 d0 83 e8 ?? 31 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Zenpak_GNS_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 8d 14 37 8b cd 89 54 24 ?? 89 44 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}