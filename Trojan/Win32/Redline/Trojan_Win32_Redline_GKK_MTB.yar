
rule Trojan_Win32_Redline_GKK_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 3c ?? ?? ?? ?? 03 c6 59 8b 4c 24 ?? 0f b6 c0 8a 84 04 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 89 4c 24 ?? 81 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GKK_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e7 89 c8 29 d0 d1 e8 01 d0 c1 e8 ?? 6b c0 ?? 01 c8 c1 e8 ?? 0f be 80 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 89 c2 c1 ea ?? c1 e8 ?? 01 d0 c0 e0 ?? 30 84 0e ?? ?? ?? ?? 83 c1 ?? 81 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}