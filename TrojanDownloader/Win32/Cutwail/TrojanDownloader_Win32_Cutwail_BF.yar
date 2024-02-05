
rule TrojanDownloader_Win32_Cutwail_BF{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 42 50 50 8b 4d fc 8b 51 34 52 } //01 00 
		$a_01_1 = {03 51 28 8b 45 14 89 10 } //02 00 
		$a_03_2 = {0f b6 42 03 35 90 01 04 8b 4d 08 03 4d fc 88 41 03 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}