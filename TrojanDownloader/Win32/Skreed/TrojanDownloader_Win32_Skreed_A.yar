
rule TrojanDownloader_Win32_Skreed_A{
	meta:
		description = "TrojanDownloader:Win32/Skreed.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 64 6c 2f 65 78 2e 70 68 70 3f } //01 00  /dl/ex.php?
		$a_03_1 = {8b d8 56 53 ff 15 90 01 04 53 89 45 08 ff d7 81 7d 08 01 04 00 00 73 0d 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 81 7d 08 00 04 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}