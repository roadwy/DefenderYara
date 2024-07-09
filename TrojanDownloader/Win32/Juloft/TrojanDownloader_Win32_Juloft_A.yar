
rule TrojanDownloader_Win32_Juloft_A{
	meta:
		description = "TrojanDownloader:Win32/Juloft.A,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd3 00 ffffffd3 00 0a 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 [0-01] 2e 63 6e 2f 64 61 74 61 2f 69 70 2e 70 68 70 } //100
		$a_00_1 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //100 Internet Explorer_Server
		$a_02_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 [0-01] 2e 63 6e 2f 64 61 74 61 2f 4c 4c 2e 74 78 74 } //10
		$a_00_3 = {4c 4c 43 6f 6e 66 69 67 2e 69 6e 69 } //1 LLConfig.ini
		$a_02_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 [0-01] 2e 63 6e 2f 64 61 74 61 2f 44 4a 2e 74 78 74 } //10
		$a_00_5 = {44 4a 43 6f 6e 66 69 67 2e 69 6e 69 } //1 DJConfig.ini
		$a_02_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 [0-01] 2e 63 6e 2f 64 61 74 61 2f 74 6a 2f 63 6f 75 6e 74 2e 70 68 70 3f 4d 41 43 3d } //100
		$a_00_7 = {5c 4d 65 64 69 61 5c 57 69 6e 64 6f 77 73 20 4e 61 76 69 67 61 74 69 6f 6e 20 53 74 61 72 74 2e 77 61 76 } //100 \Media\Windows Navigation Start.wav
		$a_02_8 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 [0-01] 2e 63 6e 2f 64 61 74 61 2f 54 43 2e 74 78 74 } //10
		$a_00_9 = {54 43 43 6f 6e 66 69 67 2e 69 6e 69 } //1 TCConfig.ini
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*100+(#a_02_2  & 1)*10+(#a_00_3  & 1)*1+(#a_02_4  & 1)*10+(#a_00_5  & 1)*1+(#a_02_6  & 1)*100+(#a_00_7  & 1)*100+(#a_02_8  & 1)*10+(#a_00_9  & 1)*1) >=211
 
}
rule TrojanDownloader_Win32_Juloft_A_2{
	meta:
		description = "TrojanDownloader:Win32/Juloft.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 2e 63 6e 2f 64 61 74 61 2f 64 61 74 61 2e 68 74 6d 6c } //1 http://www.julysoft.cn/data/data.html
		$a_01_1 = {6a 75 6c 79 73 6f 66 74 2e 65 78 65 } //1 julysoft.exe
		$a_01_2 = {6a 61 76 61 73 63 72 69 70 74 3a } //1 javascript:
		$a_01_3 = {61 62 6f 75 74 2e 69 6e 69 } //1 about.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_Win32_Juloft_A_3{
	meta:
		description = "TrojanDownloader:Win32/Juloft.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 2e 63 6e 2f 64 61 74 61 2f 61 62 6f 75 74 2e 68 74 6d 6c 3f } //1 http://www.julysoft.cn/data/about.html?
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6a 75 6c 79 73 6f 66 74 31 2e 63 6e 2f 64 61 74 61 2f 74 6a 2f 63 6f 75 6e 74 2e 70 68 70 3f 4d 41 43 3d } //1 http://www.julysoft1.cn/data/tj/count.php?MAC=
		$a_01_2 = {64 6c 6c 63 61 63 68 65 5c 63 69 73 76 63 2e 65 78 65 } //1 dllcache\cisvc.exe
		$a_01_3 = {73 63 20 63 6f 6e 66 69 67 20 43 69 53 76 63 20 73 74 61 72 74 3d 20 61 75 74 6f } //1 sc config CiSvc start= auto
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}