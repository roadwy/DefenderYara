
rule TrojanDownloader_Win32_Banload_OW{
	meta:
		description = "TrojanDownloader:Win32/Banload.OW,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea 32 e8 90 01 03 ff 8b 55 f4 8d 45 f8 e8 90 01 03 ff 43 4e 75 dc 90 00 } //01 00 
		$a_01_1 = {6f 20 61 72 71 75 69 76 6f } //01 00  o arquivo
		$a_01_2 = {4d 73 6e 48 6f 74 } //00 00  MsnHot
	condition:
		any of ($a_*)
 
}