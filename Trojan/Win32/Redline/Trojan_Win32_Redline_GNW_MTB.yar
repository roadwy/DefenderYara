
rule Trojan_Win32_Redline_GNW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d7 80 b6 ?? ?? ?? ?? ?? 53 53 53 ff d7 80 86 ?? ?? ?? ?? ?? 53 53 53 ff d7 80 86 ?? ?? ?? ?? ?? 46 81 fe } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GNW_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 c1 8d 0c 2e 33 c1 2b f8 8b d7 c1 e2 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 89 54 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}