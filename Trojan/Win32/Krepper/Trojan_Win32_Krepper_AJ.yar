
rule Trojan_Win32_Krepper_AJ{
	meta:
		description = "Trojan:Win32/Krepper.AJ,SIGNATURE_TYPE_PEHSTR,fffffff1 00 fffffff0 00 08 00 00 "
		
	strings :
		$a_01_0 = {4d 00 65 00 6c 00 6b 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //100 Melkosoft Corporation
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 69 6e 2d 65 74 6f 2e 63 6f 6d 2f 68 70 2e 68 74 6d } //100 http://win-eto.com/hp.htm
		$a_01_2 = {48 6f 6f 6b 50 72 6f 63 } //10 HookProc
		$a_01_3 = {43 61 73 73 61 6e 64 72 61 } //10 Cassandra
		$a_01_4 = {41 70 70 49 6e 69 74 5f 44 4c 4c 73 } //10 AppInit_DLLs
		$a_01_5 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //10 UnhookWindowsHookEx
		$a_01_6 = {35 46 34 33 45 37 31 36 2d 35 39 36 43 2d 34 66 62 38 2d 42 31 31 42 2d 34 44 32 36 38 46 33 43 44 41 46 41 2d 56 33 34 } //1 5F43E716-596C-4fb8-B11B-4D268F3CDAFA-V34
		$a_01_7 = {34 45 37 34 45 30 45 46 2d 44 34 32 34 2d 34 30 31 32 2d 42 43 43 44 2d 31 30 39 37 43 35 43 42 36 46 43 37 2d 56 33 34 } //1 4E74E0EF-D424-4012-BCCD-1097C5CB6FC7-V34
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=240
 
}