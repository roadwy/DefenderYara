
rule Worm_Win32_Kozy_A{
	meta:
		description = "Worm:Win32/Kozy.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 2e 00 6f 00 7a 00 79 00 } //1 control.ozy
		$a_01_1 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 } //1 smtp.gmail.
		$a_01_2 = {6f 70 65 6e 3d 61 75 74 6f 72 75 6e 2e 65 78 65 } //1 open=autorun.exe
		$a_01_3 = {5b 61 75 74 6f 72 75 6e 5d } //1 [autorun]
		$a_01_4 = {77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 73 00 3a 00 5c 00 5c 00 2e 00 5c 00 72 00 6f 00 6f 00 74 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 } //1 winmgmts:\\.\root\SecurityCenter
		$a_01_5 = {64 65 6c 20 63 3a 5c 5c 77 69 6e 64 6f 77 73 5c 5c 73 79 73 74 65 6d 33 32 5c 5c 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c } //1 del c:\\windows\\system32\\kernel32.dll
		$a_01_6 = {5b 00 44 00 65 00 6c 00 65 00 74 00 65 00 5d 00 } //1 [Delete]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}