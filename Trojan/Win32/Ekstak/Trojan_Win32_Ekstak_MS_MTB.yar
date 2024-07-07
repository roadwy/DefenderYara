
rule Trojan_Win32_Ekstak_MS_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {44 45 53 54 52 4f 59 4b 45 59 44 4c 47 } //1 DESTROYKEYDLG
		$a_81_1 = {50 41 53 53 57 4f 52 44 5f 4c 4f 41 44 5f 44 4c 47 } //1 PASSWORD_LOAD_DLG
		$a_81_2 = {45 6e 74 65 72 20 73 65 63 75 72 69 74 79 20 70 61 73 73 77 6f 72 64 } //1 Enter security password
		$a_81_3 = {74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //1 t Explorer_Server
		$a_81_4 = {73 71 6c 69 74 65 33 2e 64 6c 6c } //1 sqlite3.dll
		$a_81_5 = {5f 65 78 63 65 70 74 5f 68 61 6e 64 6c 65 72 33 } //1 _except_handler3
		$a_81_6 = {5f 5f 67 65 74 6d 61 69 6e 61 72 67 73 } //1 __getmainargs
		$a_81_7 = {5f 5f 73 65 74 75 73 65 72 6d 61 74 68 65 72 72 } //1 __setusermatherr
		$a_81_8 = {5f 5f 70 5f 5f 66 6d 6f 64 65 } //1 __p__fmode
		$a_81_9 = {5f 63 6f 6e 74 72 6f 6c 66 70 } //1 _controlfp
		$a_81_10 = {4f 66 66 73 65 74 52 65 63 74 } //1 OffsetRect
		$a_81_11 = {53 65 74 43 61 70 74 75 72 65 } //1 SetCapture
		$a_81_12 = {44 6c 6c 49 6e 73 74 61 6c 6c } //1 DllInstall
		$a_81_13 = {43 73 72 46 72 65 65 43 61 70 74 75 72 65 42 75 66 66 65 72 } //1 CsrFreeCaptureBuffer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}