
rule TrojanDownloader_Win32_Sality_AT{
	meta:
		description = "TrojanDownloader:Win32/Sality.AT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 c1 00 04 00 00 89 8d 90 01 02 ff ff 8b 95 90 01 02 ff ff 3b 95 90 01 02 ff ff 73 90 01 01 8d 85 90 01 02 ff ff 50 8b 0d 90 01 04 51 ff 15 90 01 04 50 8b 15 90 01 04 52 e8 90 01 04 83 c4 0c 8d 85 90 01 02 ff ff 50 68 00 04 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}