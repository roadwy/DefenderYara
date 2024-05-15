
rule TrojanDownloader_Win32_Pikabot_VH_MTB{
	meta:
		description = "TrojanDownloader:Win32/Pikabot.VH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f6 0f b6 54 15 90 01 01 33 ca b8 90 01 04 c1 e0 90 01 01 0f be 94 05 90 01 04 c1 e2 90 01 01 b8 90 01 04 6b c0 90 01 01 0f be 84 05 90 01 04 0f af d0 6b d2 90 01 01 8b 45 90 01 01 2b c2 8b 55 90 01 01 88 0c 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}