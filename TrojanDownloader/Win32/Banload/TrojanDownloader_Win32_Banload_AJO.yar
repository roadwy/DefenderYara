
rule TrojanDownloader_Win32_Banload_AJO{
	meta:
		description = "TrojanDownloader:Win32/Banload.AJO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 fb 01 75 df a1 90 01 01 b7 40 00 e8 90 01 02 ff ff 6a 00 68 90 01 02 40 00 68 90 01 02 40 00 6a 00 e8 90 01 02 ff ff e9 90 01 01 01 00 00 8d 55 cc 33 c0 e8 90 01 02 ff ff 8b 55 cc b8 90 01 02 40 00 e8 90 01 02 ff ff 85 c0 0f 8e 90 01 01 01 00 00 b8 90 01 01 b7 40 00 ba 90 01 02 40 00 90 00 } //01 00 
		$a_01_1 = {6e 69 63 00 ff ff ff ff 07 00 00 00 68 61 6e 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}