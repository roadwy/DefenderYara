
rule TrojanDownloader_Win32_Banload_APS{
	meta:
		description = "TrojanDownloader:Win32/Banload.APS,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {e8 fc 17 f6 ff 8d 45 f4 ba 90 01 02 4a 00 e8 53 3e f6 ff 8d 45 f8 ba 90 01 02 4a 00 e8 46 3e f6 ff 8d 45 fc ba 90 01 02 4a 00 e8 39 3e f6 ff b8 03 00 00 00 e8 f3 17 f6 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}