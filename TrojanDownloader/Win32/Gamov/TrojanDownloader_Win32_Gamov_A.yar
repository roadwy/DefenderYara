
rule TrojanDownloader_Win32_Gamov_A{
	meta:
		description = "TrojanDownloader:Win32/Gamov.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 55 49 44 54 61 6f 00 } //01 00  啇䑉慔o
		$a_03_1 = {74 61 6f 62 61 6f 2e 69 63 6f 90 01 06 6d 6f 76 69 65 2e 69 63 6f 90 01 03 6d 6d 2e 69 63 6f 90 01 06 67 61 6d 65 2e 69 63 6f 90 00 } //01 00 
		$a_01_2 = {4c 6f 76 65 33 36 30 3d 34 2a 39 30 2b 52 2b 69 6e 67 2a 33 36 30 } //01 00  Love360=4*90+R+ing*360
		$a_01_3 = {36 31 72 72 2e 63 6f 6d } //00 00  61rr.com
	condition:
		any of ($a_*)
 
}