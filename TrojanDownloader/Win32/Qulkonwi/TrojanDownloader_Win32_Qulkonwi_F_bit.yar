
rule TrojanDownloader_Win32_Qulkonwi_F_bit{
	meta:
		description = "TrojanDownloader:Win32/Qulkonwi.F!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b7 44 70 fe 33 c3 89 45 90 01 01 3b 7d 90 01 01 7c 0f 8b 45 90 01 01 05 ff 00 00 00 2b c7 89 45 90 01 01 eb 03 90 00 } //01 00 
		$a_03_1 = {6a 01 6a 00 6a 00 8d 8d 90 01 03 ff ba 90 01 03 00 b8 90 01 03 00 e8 90 01 03 ff 8b 85 90 01 03 ff e8 90 01 03 ff 50 6a 00 8b c3 e8 90 01 03 ff 50 e8 90 01 03 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}