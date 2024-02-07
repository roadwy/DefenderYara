
rule TrojanDownloader_Win32_Daumy_A{
	meta:
		description = "TrojanDownloader:Win32/Daumy.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0e 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 69 74 65 48 6f 73 74 22 20 20 22 63 6c 69 63 6b 75 72 6c } //01 00  siteHost"  "clickurl
		$a_00_1 = {64 61 75 6d 2e 6e 65 74 } //01 00  daum.net
		$a_00_2 = {72 63 32 35 2e 6f 76 65 72 74 75 72 65 2e 63 6f 6d } //01 00  rc25.overture.com
		$a_00_3 = {73 65 61 72 63 68 2e 6e 61 76 65 72 2e 63 6f 6d } //01 00  search.naver.com
		$a_00_4 = {34 30 34 2e 64 75 6d 6d 79 77 65 62 73 69 74 65 64 61 74 61 62 61 73 65 2e 63 6f 6d } //01 00  404.dummywebsitedatabase.com
		$a_01_5 = {72 65 66 65 72 75 72 6c 3d 25 73 26 70 61 67 65 75 72 6c 3d 25 73 26 70 3d 30 26 64 6f 6d 69 6e 66 6f } //01 00  referurl=%s&pageurl=%s&p=0&dominfo
		$a_01_6 = {25 73 2c 25 73 2c 4d 49 4e 49 2c 59 2c 73 70 6f 6e 73 6f 72 2c 73 70 6f 6e 73 6f 72 2c 4e 2c 25 64 2c 2d 31 2c 58 2c 25 64 2c 31 } //05 00  %s,%s,MINI,Y,sponsor,sponsor,N,%d,-1,X,%d,1
		$a_03_7 = {8b 44 24 68 8b 4c 24 64 8b 54 24 60 6a 05 50 51 52 68 90 01 04 6a 00 ff 15 90 00 } //05 00 
		$a_03_8 = {8b 50 08 51 8b 48 04 52 8b 10 51 52 8d 44 24 14 68 90 01 04 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}