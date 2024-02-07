
rule Trojan_Win32_CryptInject_CM_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 3a 5c 77 6f 72 6b 5c 70 72 6f 64 75 63 74 53 76 63 5c 4f 75 74 50 75 74 46 69 6c 65 5c 52 65 6c 65 61 73 65 5c 53 65 76 65 6e 44 61 79 42 4a 53 76 63 2e 70 64 62 } //01 00  E:\work\productSvc\OutPutFile\Release\SevenDayBJSvc.pdb
		$a_81_1 = {53 65 76 65 6e 44 61 79 42 4a 2e 65 78 65 } //01 00  SevenDayBJ.exe
		$a_81_2 = {53 65 76 65 6e 44 61 79 42 4a 20 53 65 72 76 69 63 65 } //01 00  SevenDayBJ Service
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_4 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 57 } //01 00  OutputDebugStringW
		$a_01_5 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //01 00  QueryPerformanceCounter
		$a_01_6 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 36 34 } //00 00  GetTickCount64
	condition:
		any of ($a_*)
 
}