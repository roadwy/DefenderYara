
rule Trojan_Win32_Vidar_GFK_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GFK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 00 0f b6 d0 8b 45 ec 0f b6 44 85 cb 0f b6 c0 89 54 24 04 89 04 24 e8 90 01 04 89 c3 8b 45 ec 8d 14 85 00 00 00 00 8b 45 08 8d 0c 02 89 f2 31 da 8b 45 e8 01 c8 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}