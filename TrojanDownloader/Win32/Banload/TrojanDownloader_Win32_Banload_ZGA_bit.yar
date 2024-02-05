
rule TrojanDownloader_Win32_Banload_ZGA_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZGA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 55 e7 b9 01 00 00 00 8b c6 8b 38 ff 57 0c 8b 4d e8 0f b7 45 e4 d3 e8 f6 d0 30 45 e7 8d 55 e7 b9 01 00 00 00 8b 45 ec 8b 38 ff 57 10 ff 45 e8 4b 75 cd } //01 00 
		$a_03_1 = {6a 04 68 00 20 00 00 8b 85 10 ff ff ff 50 8b 85 f4 fe ff ff 50 e8 90 01 03 ff 8b d8 85 db 75 17 6a 04 68 00 20 00 00 8b 85 10 ff ff ff 50 6a 00 e8 90 01 03 ff 8b d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}