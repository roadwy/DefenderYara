
rule TrojanSpy_Win32_Gimmiv_A{
	meta:
		description = "TrojanSpy:Win32/Gimmiv.A,SIGNATURE_TYPE_PEHSTR_EXT,50 00 50 00 14 00 00 "
		
	strings :
		$a_00_0 = {57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //10 WScript.CreateObject("Scripting.FileSystemObject")
		$a_00_1 = {72 65 67 20 64 65 6c 65 74 65 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //10 reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost
		$a_00_2 = {72 65 67 20 64 65 6c 65 74 65 20 22 48 4b 4c 4d 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //10 reg delete "HKLM\SYSTEM\CurrentControlSet\Services\%s
		$a_00_3 = {6e 65 74 20 73 74 6f 70 20 25 73 } //10 net stop %s
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_02_5 = {2e 76 62 73 90 02 10 6e 6f 74 65 70 61 64 2e 65 78 65 90 00 } //10
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 42 69 74 44 65 66 65 6e 64 65 72 } //2 SOFTWARE\BitDefender
		$a_00_7 = {53 4f 46 54 57 41 52 45 5c 4a 69 61 6e 67 6d 69 6e } //2 SOFTWARE\Jiangmin
		$a_00_8 = {53 4f 46 54 57 41 52 45 5c 4b 61 73 70 65 72 73 6b 79 4c 61 62 } //2 SOFTWARE\KasperskyLab
		$a_00_9 = {53 4f 46 54 57 41 52 45 5c 4b 69 6e 67 73 6f 66 74 } //2 SOFTWARE\Kingsoft
		$a_00_10 = {53 4f 46 54 57 41 52 45 5c 53 79 6d 61 6e 74 65 63 5c 50 61 74 63 68 49 6e 73 74 5c 4e 49 53 } //2 SOFTWARE\Symantec\PatchInst\NIS
		$a_00_11 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 6e 65 43 61 72 65 20 50 72 6f 74 65 63 74 69 6f 6e } //2 SOFTWARE\Microsoft\OneCare Protection
		$a_00_12 = {53 4f 46 54 57 41 52 45 5c 72 69 73 69 6e 67 } //2 SOFTWARE\rising
		$a_00_13 = {53 4f 46 54 57 41 52 45 5c 54 72 65 6e 64 4d 69 63 72 6f } //2 SOFTWARE\TrendMicro
		$a_00_14 = {44 65 63 72 79 70 74 46 69 6c 65 41 45 53 } //1 DecryptFileAES
		$a_00_15 = {2e 44 65 6c 65 74 65 46 69 6c 65 20 22 25 73 } //1 .DeleteFile "%s
		$a_00_16 = {6e 78 72 65 73 74 61 72 74 2e 62 61 74 } //1 nxrestart.bat
		$a_00_17 = {6e 62 7a 63 6c 65 61 6e 2e 62 61 74 } //1 nbzclean.bat
		$a_00_18 = {63 74 66 6d 6f 6e 2e 65 78 65 } //1 ctfmon.exe
		$a_00_19 = {57 53 63 72 69 70 74 2e 53 6c 65 65 70 } //1 WScript.Sleep
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_02_5  & 1)*10+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*2+(#a_00_9  & 1)*2+(#a_00_10  & 1)*2+(#a_00_11  & 1)*2+(#a_00_12  & 1)*2+(#a_00_13  & 1)*2+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1+(#a_00_19  & 1)*1) >=80
 
}