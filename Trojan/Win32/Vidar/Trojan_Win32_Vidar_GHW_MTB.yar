
rule Trojan_Win32_Vidar_GHW_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6b e9 5c 3d 0f be 45 99 0f be 4d 9a 2b c1 88 45 99 0f be 45 e7 99 35 90 01 04 81 f2 90 01 04 66 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Vidar_GHW_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.GHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 84 3c 90 01 04 88 84 34 90 01 04 88 8c 3c 90 01 04 0f b6 84 34 90 01 04 03 c2 0f b6 c0 0f b6 84 04 90 01 04 30 83 90 01 04 43 81 fb 00 56 05 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}