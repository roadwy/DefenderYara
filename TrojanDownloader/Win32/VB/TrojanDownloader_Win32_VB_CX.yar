
rule TrojanDownloader_Win32_VB_CX{
	meta:
		description = "TrojanDownloader:Win32/VB.CX,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {6d 00 74 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 2e 00 76 00 62 00 70 00 } //2 mt Download .vbp
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //2 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 6d 00 73 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //2 system32\smsss.exe
		$a_01_3 = {72 00 65 00 63 00 76 00 2e 00 61 00 73 00 70 00 3f 00 } //1 recv.asp?
		$a_01_4 = {26 00 3d 00 76 00 69 00 70 00 31 00 26 00 3d 00 } //1 &=vip1&=
		$a_01_5 = {74 00 68 00 65 00 74 00 61 00 73 00 6b 00 73 00 2e 00 61 00 73 00 70 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 } //1 thetasks.asp?action
		$a_01_6 = {26 00 70 00 68 00 79 00 53 00 65 00 72 00 3d 00 } //1 &phySer=
		$a_01_7 = {5c 00 5c 00 2e 00 5c 00 53 00 4d 00 41 00 52 00 54 00 56 00 53 00 44 00 } //1 \\.\SMARTVSD
		$a_01_8 = {66 00 75 00 63 00 6b 00 } //1 fuck
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}