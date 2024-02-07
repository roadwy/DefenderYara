
rule TrojanSpy_Win32_Delf_HJ{
	meta:
		description = "TrojanSpy:Win32/Delf.HJ,SIGNATURE_TYPE_PEHSTR,13 00 13 00 13 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 7a 5c 4f 70 65 6e 49 65 32 } //01 00  Software\Mz\OpenIe2
		$a_01_2 = {4f 70 65 6e 49 65 20 32 30 30 36 } //01 00  OpenIe 2006
		$a_01_3 = {49 45 46 72 61 6d 65 } //01 00  IEFrame
		$a_01_4 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d } //01 00  [InternetShortcut]
		$a_01_5 = {75 72 6c 2e 64 6c 6c } //01 00  url.dll
		$a_01_6 = {54 44 6f 77 6e 49 6e 66 6f } //01 00  TDownInfo
		$a_01_7 = {5b 53 65 74 75 70 61 68 6f 6d 65 70 61 67 65 5d } //01 00  [Setupahomepage]
		$a_01_8 = {5b 49 6e 74 65 72 70 6f 73 65 63 6f 6c 6c 65 63 74 5d } //01 00  [Interposecollect]
		$a_01_9 = {5b 44 6f 77 6e 6c 6f 61 64 70 72 6f 63 65 64 75 72 65 5d } //01 00  [Downloadprocedure]
		$a_01_10 = {5b 43 6f 6e 63 65 61 6c 64 61 72 6b 62 61 6c 6c 5d } //01 00  [Concealdarkball]
		$a_01_11 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //01 00  Content-Type: application/x-www-form-urlencoded
		$a_01_12 = {68 74 74 70 3a 2f 2f 77 77 77 2e 68 61 6f 31 32 33 2e 63 6f 6d 2f } //01 00  http://www.hao123.com/
		$a_01_13 = {68 74 74 70 3a 2f 2f 76 69 70 2e 7a 65 69 77 61 6e 67 2e 63 6e 2f 69 6d 61 67 65 73 2f 6c 6f 67 6f 2e 67 69 66 } //01 00  http://vip.zeiwang.cn/images/logo.gif
		$a_01_14 = {53 74 61 72 74 20 50 61 67 65 } //01 00  Start Page
		$a_01_15 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //01 00  Software\Microsoft\Internet Explorer\Main
		$a_01_16 = {54 61 73 6b 4d 67 72 2e 45 78 65 } //01 00  TaskMgr.Exe
		$a_01_17 = {56 65 72 43 4c 53 49 44 2e 65 78 65 } //01 00  VerCLSID.exe
		$a_01_18 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //00 00  InternetReadFile
	condition:
		any of ($a_*)
 
}