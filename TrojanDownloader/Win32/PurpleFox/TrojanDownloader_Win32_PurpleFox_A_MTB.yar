
rule TrojanDownloader_Win32_PurpleFox_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/PurpleFox.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {57 ff d6 68 90 01 04 8b f8 ff 15 90 01 04 ff d6 2b c7 5f 3d 90 01 04 5e 0f 9c c0 90 00 } //02 00 
		$a_03_1 = {57 ff d6 bf 90 01 04 8b d8 57 ff 15 90 01 04 ff d6 2b c3 3b c7 5f 5e 5b 0f 9c c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}