
rule Trojan_Win32_Stealerc_GKH_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 50 01 8b 85 90 01 04 01 c2 8b 85 90 01 04 83 e8 01 2b 85 90 01 04 0f b6 84 05 90 01 04 88 84 15 90 01 04 8b 85 90 01 04 83 e8 01 2b 85 90 01 04 0f b6 95 90 01 04 88 94 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}