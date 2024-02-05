
rule TrojanDownloader_Win32_Banload_ZFZ_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZFZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 54 24 10 b9 01 00 00 00 8b c6 8b 28 ff 55 0c 8b cf 0f b7 44 24 12 d3 e8 f6 d0 30 44 24 10 8d 54 24 10 b9 01 00 00 00 8b 44 24 0c 8b 28 ff 55 10 47 4b 75 cb } //01 00 
		$a_03_1 = {68 00 10 00 00 8b 85 10 ff ff ff 50 53 e8 90 01 03 ff 6a 04 68 00 10 00 00 8b 85 14 ff ff ff 50 53 e8 90 01 03 ff 8b f8 8b 4d f4 03 8d 14 ff ff ff 8b 16 8b c7 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}