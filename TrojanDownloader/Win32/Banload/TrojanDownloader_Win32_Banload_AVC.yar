
rule TrojanDownloader_Win32_Banload_AVC{
	meta:
		description = "TrojanDownloader:Win32/Banload.AVC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 b8 44 00 e8 90 01 04 6a 00 6a 00 6a 00 6a 00 8b 45 90 01 01 e8 90 01 04 50 e8 90 00 } //01 00 
		$a_03_1 = {66 b8 44 00 e8 90 01 04 8b 45 f8 e8 90 01 04 50 6a 00 e8 90 01 04 83 f8 20 0f 97 c3 33 c0 90 00 } //01 00 
		$a_03_2 = {bf 00 01 00 00 66 83 eb 43 74 0e 66 ff cb 0f 84 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}