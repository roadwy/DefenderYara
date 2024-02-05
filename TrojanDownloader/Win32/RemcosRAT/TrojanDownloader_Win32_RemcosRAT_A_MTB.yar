
rule TrojanDownloader_Win32_RemcosRAT_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/RemcosRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b c8 0f b7 c3 8b ea 99 03 c8 13 d5 33 c0 33 c8 33 d7 8b f9 } //00 00 
	condition:
		any of ($a_*)
 
}