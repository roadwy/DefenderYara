
rule Backdoor_Win32_Venik_I{
	meta:
		description = "Backdoor:Win32/Venik.I,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 47 52 79 61 58 5a 6c 63 6e 4e 63 5a 58 52 6a 58 47 68 76 63 33 52 7a 4c 6d 6c 6a 63 77 3d 3d } //01 00  XGRyaXZlcnNcZXRjXGhvc3RzLmljcw==
		$a_01_1 = {55 31 6c 54 56 45 56 4e 58 45 4e 31 63 6e 4a 6c 62 6e 52 44 62 32 35 30 63 6d 39 73 55 32 56 30 58 46 4e 6c 63 6e 5a 70 59 32 56 7a 58 46 4a 6c 62 57 39 30 5a 55 46 6a 59 32 56 7a 63 31 78 53 62 33 56 30 5a 58 4a 4e 59 57 35 68 5a 32 56 79 63 31 78 4a 63 41 3d 3d } //01 00  U1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XFNlcnZpY2VzXFJlbW90ZUFjY2Vzc1xSb3V0ZXJNYW5hZ2Vyc1xJcA==
		$a_01_2 = {55 30 39 47 56 46 64 42 55 6b 56 63 51 57 68 75 54 47 46 69 58 46 59 7a 54 47 6c 30 5a 51 3d 3d } //02 00  U09GVFdBUkVcQWhuTGFiXFYzTGl0ZQ==
		$a_03_3 = {7c 73 65 61 72 63 68 2e 64 61 75 6d 2e 6e 65 74 7c 73 65 61 72 63 68 2e 6e 61 76 65 72 2e 63 6f 6d 7c 77 77 77 2e 6b 62 73 74 61 72 2e 90 05 10 04 61 2d 7a 2e 7c 77 77 77 2e 6b 6e 62 61 6e 6b 2e 90 05 10 04 61 2d 7a 2e 7c 6f 70 65 6e 62 61 6e 6b 90 05 10 04 61 2d 7a 2e 7c 77 77 77 2e 62 75 73 61 6e 62 61 6e 6b 2e 90 05 10 04 61 2d 7a 2e 7c 90 00 } //02 00 
		$a_01_4 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 28 53 76 63 68 6f 73 74 5c 6b 72 6e 6c 73 72 76 63 29 } //00 00  RegSetValueEx(Svchost\krnlsrvc)
		$a_00_5 = {80 10 00 00 } //3d 8b 
	condition:
		any of ($a_*)
 
}