
rule TrojanDownloader_Win32_Macapy_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Macapy.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 26 8b 04 f5 90 01 03 00 8a 0c f5 90 01 03 00 0f b7 d3 f6 d1 32 0c 10 32 cb 43 88 0c 3a 66 3b 1c f5 90 01 03 00 72 da 90 00 } //01 00 
		$a_03_1 = {0f b6 04 1f 33 c1 c1 e9 08 25 ff 00 00 00 33 0c 85 90 01 03 00 47 3b fa 72 e6 90 00 } //01 00 
		$a_03_2 = {8d 0c 9e 03 4c 37 20 74 16 8b 09 03 ce e8 90 01 03 ff 8b d0 e8 90 01 03 ff 3b 44 90 01 02 74 14 43 3b 5c 37 18 72 da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}