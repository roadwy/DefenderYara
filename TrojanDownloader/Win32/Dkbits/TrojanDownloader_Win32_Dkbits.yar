
rule TrojanDownloader_Win32_Dkbits{
	meta:
		description = "TrojanDownloader:Win32/Dkbits,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0b 00 0d 00 00 "
		
	strings :
		$a_02_0 = {31 32 37 2e 30 2e 30 2e 33 90 02 10 2e 63 6f 6d 90 00 } //3
		$a_00_1 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //2 drivers\etc\hosts
		$a_00_2 = {69 66 72 61 6d 65 64 6f 6c 6c 61 72 73 2e 62 69 7a } //1 iframedollars.biz
		$a_00_3 = {64 6b 70 72 6f 67 73 } //1 dkprogs
		$a_00_4 = {64 6b 74 69 62 73 2e 65 78 65 } //1 dktibs.exe
		$a_00_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 73 79 73 74 69 6d 65 2e 65 78 65 } //1 C:\WINDOWS\SYSTEM32\systime.exe
		$a_00_6 = {65 78 70 6c 6f 69 74 2e 65 78 65 } //1 exploit.exe
		$a_00_7 = {66 75 63 6b 65 72 2e 65 78 65 } //1 fucker.exe
		$a_00_8 = {64 6c 61 64 76 } //1 dladv
		$a_00_9 = {6d 73 74 61 73 6b 73 } //1 mstasks
		$a_01_10 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_11 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e } //1 InternetOpen
		$a_00_12 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //1 TerminateProcess
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=11
 
}