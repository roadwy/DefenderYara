
rule TrojanDownloader_Win32_Nekotimed_A{
	meta:
		description = "TrojanDownloader:Win32/Nekotimed.A,SIGNATURE_TYPE_PEHSTR_EXT,18 00 16 00 0c 00 00 "
		
	strings :
		$a_01_0 = {64 6d 2e 64 65 6d 69 73 65 74 6f 6b 65 6e 2e 63 6f 6d 3a 38 36 2f 6c 6f 67 2e 61 73 70 78 3f } //4 dm.demisetoken.com:86/log.aspx?
		$a_01_1 = {2f 78 6e 2e 62 69 73 } //4 /xn.bis
		$a_01_2 = {40 77 65 6e 23 25 25 25 36 6e } //4 @wen#%%%6n
		$a_03_3 = {5b 6d 61 69 6e 5d 00 [0-15] 2e 70 68 70 00 } //4
		$a_01_4 = {64 6d 2e 63 61 72 61 76 65 6c 32 2e 63 6f 6d 3a 38 36 2f 6c 6f 67 2e 61 73 70 78 3f } //4 dm.caravel2.com:86/log.aspx?
		$a_01_5 = {83 7d f0 10 8b 45 dc 73 03 8d 45 dc ff 75 ec 50 8d 85 80 f7 ff ff 50 e8 } //4
		$a_01_6 = {77 69 6e 69 6f 2e 73 79 73 } //2 winio.sys
		$a_01_7 = {43 6f 6d 70 75 74 65 72 20 49 44 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 3a 20 25 64 } //2 Computer ID_______________________: %d
		$a_01_8 = {77 69 6e 5f 25 75 } //2 win_%u
		$a_01_9 = {6d 69 64 3d 25 73 26 61 76 3d 25 73 26 73 6e 3d 25 73 } //2 mid=%s&av=%s&sn=%s
		$a_01_10 = {46 30 32 38 31 30 42 42 39 44 34 36 36 44 7d } //2 F02810BB9D466D}
		$a_01_11 = {73 6f 66 74 5f 6c 6f 63 6b } //2 soft_lock
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_03_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2) >=22
 
}