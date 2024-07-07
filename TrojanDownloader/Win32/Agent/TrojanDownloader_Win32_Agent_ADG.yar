
rule TrojanDownloader_Win32_Agent_ADG{
	meta:
		description = "TrojanDownloader:Win32/Agent.ADG,SIGNATURE_TYPE_PEHSTR,62 00 62 00 09 00 00 "
		
	strings :
		$a_01_0 = {2f 43 20 6e 65 74 20 76 69 65 77 20 3e 63 3a 5c 6e 76 } //50 /C net view >c:\nv
		$a_01_1 = {3a 45 78 65 44 65 6c 65 74 65 } //10 :ExeDelete
		$a_01_2 = {64 65 6c 20 25 45 78 65 50 61 74 68 25 } //10 del %ExePath%
		$a_01_3 = {69 66 20 65 78 69 73 74 20 25 45 78 65 50 61 74 68 25 20 67 6f 74 6f 20 45 78 65 44 65 6c 65 74 65 } //10 if exist %ExePath% goto ExeDelete
		$a_01_4 = {64 65 6c 20 25 42 61 74 50 61 74 68 25 } //10 del %BatPath%
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //5 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_7 = {46 74 70 4f 70 65 6e 46 69 6c 65 41 } //1 FtpOpenFileA
		$a_01_8 = {49 6e 74 65 72 6e 65 74 57 72 69 74 65 46 69 6c 65 } //1 InternetWriteFile
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*5+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=98
 
}