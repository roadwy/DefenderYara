
rule TrojanDownloader_Win32_Tonfled_A{
	meta:
		description = "TrojanDownloader:Win32/Tonfled.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 47 3d 25 64 26 43 50 3d 25 64 26 4b 65 79 3d 25 64 26 4a 43 3d 25 64 26 59 50 3d 25 30 32 78 26 73 65 63 6f 6e 64 3d 25 64 26 6c 6a 3d 25 73 } //01 00 
		$a_01_1 = {8a 10 80 f2 9c 88 10 40 3b c1 75 f4 } //01 00 
		$a_01_2 = {81 fb 9f 86 01 00 0f 8d aa 01 00 00 85 d2 } //00 00 
	condition:
		any of ($a_*)
 
}