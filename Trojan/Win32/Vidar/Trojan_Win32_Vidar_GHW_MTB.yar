
rule Trojan_Win32_Vidar_GHW_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b e9 5c 3d 0f be 45 99 0f be 4d 9a 2b c1 88 45 99 0f be 45 e7 99 35 ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 66 a3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Vidar_GHW_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.GHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 3c ?? ?? ?? ?? 88 84 34 ?? ?? ?? ?? 88 8c 3c ?? ?? ?? ?? 0f b6 84 34 ?? ?? ?? ?? 03 c2 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 43 81 fb 00 56 05 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}