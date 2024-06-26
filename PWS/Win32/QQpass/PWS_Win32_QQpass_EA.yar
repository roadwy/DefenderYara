
rule PWS_Win32_QQpass_EA{
	meta:
		description = "PWS:Win32/QQpass.EA,SIGNATURE_TYPE_PEHSTR,61 01 61 01 0d 00 00 64 00 "
		
	strings :
		$a_01_0 = {5c 51 51 48 6f 6f 6b 2e 64 6c 6c } //64 00  \QQHook.dll
		$a_01_1 = {48 6f 6f 6b 53 74 72 75 63 74 } //64 00  HookStruct
		$a_01_2 = {69 6e 73 74 61 6c 6c 68 6f 6f 6b } //0a 00  installhook
		$a_01_3 = {5c 77 69 6e 73 6f 33 32 2e 73 79 73 } //0a 00  \winso32.sys
		$a_01_4 = {5c 6d 73 78 6c 33 32 2e 64 6c 6c } //0a 00  \msxl32.dll
		$a_01_5 = {5c 64 65 6c 65 2e 69 6e 69 } //0a 00  \dele.ini
		$a_01_6 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //0a 00  InternetOpenA
		$a_01_7 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_01_8 = {7b 35 32 33 43 33 33 43 42 2d 35 31 30 45 2d 34 38 35 37 2d 39 38 30 31 2d 37 38 46 31 44 38 39 32 38 37 39 43 7d } //01 00  {523C33CB-510E-4857-9801-78F1D892879C}
		$a_01_9 = {7b 33 43 45 46 46 36 43 44 2d 36 46 30 38 2d 34 65 34 64 2d 42 43 43 44 2d 46 46 37 34 31 35 32 38 38 43 33 42 7d } //01 00  {3CEFF6CD-6F08-4e4d-BCCD-FF7415288C3B}
		$a_01_10 = {5c 67 6f 70 65 6e 2e 65 78 65 } //01 00  \gopen.exe
		$a_01_11 = {63 63 53 76 63 48 73 74 2e 65 78 65 } //01 00  ccSvcHst.exe
		$a_01_12 = {52 61 76 4d 6f 6e 44 2e 65 78 65 } //00 00  RavMonD.exe
	condition:
		any of ($a_*)
 
}