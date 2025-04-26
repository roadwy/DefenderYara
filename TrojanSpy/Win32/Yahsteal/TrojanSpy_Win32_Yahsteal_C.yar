
rule TrojanSpy_Win32_Yahsteal_C{
	meta:
		description = "TrojanSpy:Win32/Yahsteal.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 55 4e 44 4c 4c 33 32 2e 45 58 45 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 2c 69 } //4 RUNDLL32.EXE C:\Windows\iexplore.exe,i
		$a_00_1 = {25 73 2f 6d 6d 25 73 2e 4c 4f 47 } //2 %s/mm%s.LOG
		$a_00_2 = {25 73 2f 70 70 25 73 2e 4c 4f 47 } //2 %s/pp%s.LOG
	condition:
		((#a_01_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=8
 
}