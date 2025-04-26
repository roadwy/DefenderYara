
rule TrojanSpy_Win32_Laqma_A{
	meta:
		description = "TrojanSpy:Win32/Laqma.A,SIGNATURE_TYPE_PEHSTR_EXT,01 01 fffffffe 00 15 00 00 "
		
	strings :
		$a_00_0 = {25 73 5c 73 79 73 74 65 6d 33 32 5c 25 73 } //50 %s\system32\%s
		$a_00_1 = {2e 5c 4c 61 6e 4d 61 6e 44 72 76 } //50 .\LanManDrv
		$a_00_2 = {5f 5f 69 6e 74 73 72 76 33 32 } //25 __intsrv32
		$a_00_3 = {5f 5f 73 72 76 6d 67 72 33 32 } //25 __srvmgr32
		$a_00_4 = {25 64 2e 25 64 2e 25 64 2e 25 64 } //25 %d.%d.%d.%d
		$a_00_5 = {77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //25 www.google.com
		$a_00_6 = {71 6d 6f 70 74 2e 64 6c 6c } //10 qmopt.dll
		$a_00_7 = {77 69 6e 69 6e 65 74 2e 64 6c 6c } //10 wininet.dll
		$a_00_8 = {69 65 78 63 68 67 2e 64 6c 6c } //10 iexchg.dll
		$a_00_9 = {6c 61 6e 6d 61 6e 77 72 6b 2e 65 78 65 } //10 lanmanwrk.exe
		$a_00_10 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //10 rundll32.exe
		$a_00_11 = {6a 70 65 67 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 jpegfile\shell\open\command
		$a_00_12 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //1 Software\Microsoft\Internet Explorer
		$a_00_13 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_14 = {53 74 61 72 74 53 65 72 76 69 63 65 41 } //1 StartServiceA
		$a_00_15 = {4f 70 65 6e 53 65 72 76 69 63 65 41 } //1 OpenServiceA
		$a_00_16 = {43 72 65 61 74 65 53 65 72 76 69 63 65 41 } //1 CreateServiceA
		$a_00_17 = {5a 77 51 75 65 72 79 53 65 72 76 69 63 65 } //1 ZwQueryService
		$a_01_18 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_19 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_01_20 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //1 InternetCloseHandle
	condition:
		((#a_00_0  & 1)*50+(#a_00_1  & 1)*50+(#a_00_2  & 1)*25+(#a_00_3  & 1)*25+(#a_00_4  & 1)*25+(#a_00_5  & 1)*25+(#a_00_6  & 1)*10+(#a_00_7  & 1)*10+(#a_00_8  & 1)*10+(#a_00_9  & 1)*10+(#a_00_10  & 1)*10+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1) >=254
 
}