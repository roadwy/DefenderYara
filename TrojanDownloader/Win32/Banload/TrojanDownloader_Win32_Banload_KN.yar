
rule TrojanDownloader_Win32_Banload_KN{
	meta:
		description = "TrojanDownloader:Win32/Banload.KN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8b 80 00 03 00 00 8b 80 20 02 00 00 ba 90 01 02 46 00 8b 08 ff 51 74 8b 45 fc 8b 80 04 03 00 00 8b 80 20 02 00 00 ba 90 01 02 46 00 8b 08 ff 51 74 6a 05 68 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}