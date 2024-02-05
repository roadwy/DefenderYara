
rule TrojanDownloader_Win32_Kanav_B{
	meta:
		description = "TrojanDownloader:Win32/Kanav.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 59 33 c0 8d bd 90 01 02 ff ff f3 ab 66 ab aa 8d 85 90 01 02 ff ff 50 68 90 01 04 e8 90 00 } //01 00 
		$a_00_1 = {38 31 41 36 41 38 44 32 30 43 41 32 41 45 } //01 00 
		$a_00_2 = {2d 73 74 61 72 74 00 73 74 61 72 74 } //01 00 
		$a_00_3 = {5c 41 59 4c 61 75 6e 63 68 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}