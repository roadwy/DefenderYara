
rule Trojan_Win32_Vidar_GKH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 3d ?? ?? ?? ?? 03 ca 0f b6 c9 8a 8c 0d ?? ?? ?? ?? 30 08 40 89 45 fc 83 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}