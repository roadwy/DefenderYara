
rule TrojanDownloader_Win32_Zlob_JN{
	meta:
		description = "TrojanDownloader:Win32/Zlob.JN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 1c 07 32 18 8b 06 88 1c 01 41 83 f9 0b 72 ed } //01 00 
		$a_03_1 = {10 75 2b 09 1d 90 01 03 10 83 65 fc 00 8d 45 90 01 01 50 8d 45 90 01 01 50 b9 90 01 03 10 e8 90 01 02 ff ff 68 90 01 03 10 e8 90 01 03 00 83 4d fc ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}