
rule Trojan_Win64_Dedok_MA_MTB{
	meta:
		description = "Trojan:Win64/Dedok.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //6 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_1 = {77 68 6f 61 6d 69 } //1 whoami
		$a_00_2 = {69 70 63 6f 6e 66 69 67 } //1 ipconfig
		$a_00_3 = {47 65 74 2d 57 6d 69 4f 62 6a 65 63 74 20 2d 43 6c 61 73 73 20 57 69 6e 33 32 5f 55 73 65 72 41 63 63 6f 75 6e 74 } //1 Get-WmiObject -Class Win32_UserAccount
		$a_00_4 = {47 65 74 2d 50 72 6f 63 65 73 73 } //1 Get-Process
		$a_00_5 = {47 65 74 2d 53 65 72 76 69 63 65 } //1 Get-Service
		$a_00_6 = {47 65 74 2d 43 68 69 6c 64 49 74 65 6d 20 45 6e 76 } //1 Get-ChildItem Env
		$a_00_7 = {47 65 74 2d 50 53 44 72 69 76 65 } //1 Get-PSDrive
		$a_02_8 = {54 65 6d 70 [0-0f] 2e 6c 6f 67 } //1
		$a_00_9 = {73 63 72 65 65 6e 73 68 6f 74 } //1 screenshot
	condition:
		((#a_00_0  & 1)*6+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_02_8  & 1)*1+(#a_00_9  & 1)*1) >=14
 
}