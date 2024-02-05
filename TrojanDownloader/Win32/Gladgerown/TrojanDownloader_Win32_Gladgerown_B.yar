
rule TrojanDownloader_Win32_Gladgerown_B{
	meta:
		description = "TrojanDownloader:Win32/Gladgerown.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {eb 09 8b 55 90 01 01 83 ea 04 89 55 90 01 01 8b 45 90 01 01 3b 45 90 01 01 72 12 8b 4d 90 01 01 8b 11 81 f2 90 01 04 8b 45 90 01 01 89 10 eb dd 90 00 } //01 00 
		$a_03_1 = {33 d0 8b 45 90 01 01 03 45 90 01 01 88 10 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 8b 55 90 01 01 3b 55 90 01 01 75 07 90 00 } //01 00 
		$a_02_2 = {25 30 38 78 00 90 02 07 25 73 5f 25 78 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}