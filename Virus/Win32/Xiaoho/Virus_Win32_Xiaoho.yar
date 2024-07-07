
rule Virus_Win32_Xiaoho{
	meta:
		description = "Virus:Win32/Xiaoho,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 0a 00 00 "
		
	strings :
		$a_01_0 = {58 00 69 00 61 00 6f 00 48 00 61 00 6f 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 } //2 XiaoHao Microsoft
		$a_01_1 = {43 57 6f 72 6d 42 65 67 69 6e } //2 CWormBegin
		$a_01_2 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 58 69 61 6f 68 61 6f 2e 65 78 65 } //2 shellexecute=Xiaohao.exe
		$a_01_3 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 58 69 61 6f 68 61 6f 2e 65 78 65 } //2 shell\Auto\command=Xiaohao.exe
		$a_01_4 = {58 31 34 6f 2d 48 34 6f 27 73 20 56 69 72 75 73 } //2 X14o-H4o's Virus
		$a_01_5 = {6f 70 65 6e 3d 58 69 61 6f 68 61 6f 2e 65 78 65 0d 0a 00 00 5b 41 75 74 6f 72 75 6e 5d } //2
		$a_01_6 = {69 66 72 61 6d 65 20 73 72 63 3d 68 74 74 70 3a 2f 2f 78 69 61 6f 68 61 6f 2e 79 6f 6e 61 2e 62 69 7a 2f 78 69 61 6f 68 61 6f 2e 68 74 6d } //2 iframe src=http://xiaohao.yona.biz/xiaohao.htm
		$a_01_7 = {63 3a 5c 4a 69 6c 75 2e 74 78 74 } //1 c:\Jilu.txt
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c 7b 48 39 49 31 32 52 42 30 33 2d 41 42 2d 42 37 30 2d 37 2d 31 31 64 32 2d 39 43 42 44 2d 30 4f 30 30 46 53 37 41 48 36 2d 39 45 32 31 32 31 42 48 4a 4c 4b 7d } //1 SOFTWARE\Microsoft\Active Setup\Installed Components\{H9I12RB03-AB-B70-7-11d2-9CBD-0O00FS7AH6-9E2121BHJLK}
		$a_00_9 = {8b 35 f0 12 40 00 57 6a 01 8d 45 b4 6a 40 50 ff d6 83 c4 10 66 81 7d b4 4d 5a 75 e0 6a 00 ff 75 f0 57 ff 15 ec 12 40 00 57 6a 01 8d 85 bc fe ff ff 68 f8 00 00 00 50 ff d6 83 c4 1c 81 bd bc fe ff ff 50 45 00 00 75 05 6a 01 5e eb 02 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*2) >=8
 
}