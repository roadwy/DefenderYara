
rule TrojanDownloader_Win32_Banload_OV{
	meta:
		description = "TrojanDownloader:Win32/Banload.OV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 4a 08 33 c9 89 4a 0c 8d 7a 14 be 90 01 04 b9 08 00 00 00 f3 a5 8d 7a 34 be 90 01 04 b9 10 00 00 00 f3 a5 8d 7a 74 be 90 01 04 b9 20 00 00 00 f3 a5 eb 90 01 01 33 c0 eb 90 00 } //1
		$a_01_1 = {66 6c 61 73 68 62 61 63 6b 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Banload_OV_2{
	meta:
		description = "TrojanDownloader:Win32/Banload.OV,SIGNATURE_TYPE_PEHSTR,15 00 15 00 0a 00 00 "
		
	strings :
		$a_01_0 = {70 75 6d 61 6e 65 77 2e 64 6c 6c 00 43 50 6c 41 70 70 6c 65 74 } //10
		$a_01_1 = {76 65 74 6e 65 77 2e 64 6c 6c 00 43 50 6c 41 70 70 6c 65 74 } //10 敶湴睥搮汬䌀汐灁汰瑥
		$a_01_2 = {66 6c 61 73 68 62 61 63 6b 2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 } //10
		$a_01_3 = {5c 50 72 6f 6a 65 74 6f 73 5c 4a 61 76 61 6e 5c 73 74 61 72 74 5c 70 75 6d 61 6e 65 77 5c 70 75 6d 61 6e 65 77 2e 64 70 72 } //10 \Projetos\Javan\start\pumanew\pumanew.dpr
		$a_01_4 = {5c 50 72 6f 6a 65 74 6f 73 5c 4a 61 76 61 6e 5c 73 74 61 72 74 5c 76 65 74 6e 65 77 5c 76 65 74 6e 65 77 2e 64 70 72 } //10 \Projetos\Javan\start\vetnew\vetnew.dpr
		$a_01_5 = {5c 50 72 6f 6a 65 74 6f 73 5c 4a 61 76 61 6e 5c 73 74 61 72 74 5c 70 75 6d 61 6e 65 77 5f 31 5c 66 6c 61 73 68 62 61 63 6b 2e 64 70 72 } //10 \Projetos\Javan\start\pumanew_1\flashback.dpr
		$a_01_6 = {89 45 e8 33 ff 8d 45 d8 50 b9 02 00 00 00 ba 01 00 00 00 8b 45 f0 e8 } //1
		$a_01_7 = {38 39 42 30 35 37 45 41 31 44 44 42 30 46 30 43 37 35 44 34 41 32 } //1 89B057EA1DDB0F0C75D4A2
		$a_01_8 = {39 45 46 46 36 44 39 32 33 32 45 30 34 44 37 45 43 41 30 35 33 33 31 45 33 36 45 32 30 45 33 42 } //1 9EFF6D9232E04D7ECA05331E36E20E3B
		$a_01_9 = {50 6a 00 6a 00 6a 20 6a 00 6a 00 6a 00 53 6a 00 e8 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=21
 
}