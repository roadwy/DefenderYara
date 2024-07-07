
rule Worm_Win32_Autorun_VR{
	meta:
		description = "Worm:Win32/Autorun.VR,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 76 69 70 70 2e 73 69 74 65 67 6f 6f 67 6c 65 2e 63 6e 2f 73 75 70 65 72 6a 2e 61 73 70 } //1 http://vipp.sitegoogle.cn/superj.asp
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 2f } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options/
		$a_01_3 = {4b 41 56 50 46 57 2e 65 78 65 } //1 KAVPFW.exe
		$a_01_4 = {52 61 76 4d 6f 6e 2e 65 78 65 } //1 RavMon.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}