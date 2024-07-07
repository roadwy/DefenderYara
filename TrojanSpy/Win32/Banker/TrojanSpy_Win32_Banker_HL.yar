
rule TrojanSpy_Win32_Banker_HL{
	meta:
		description = "TrojanSpy:Win32/Banker.HL,SIGNATURE_TYPE_PEHSTR,20 00 20 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {25 31 32 73 20 20 25 38 64 20 25 37 73 20 25 30 32 64 2d 25 30 32 64 } //10 %12s  %8d %7s %02d-%02d
		$a_01_2 = {2a 2e 6b 65 79 00 00 00 2a 2e 63 72 74 } //10
		$a_01_3 = {77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 63 65 72 74 69 66 65 78 70 58 50 2e 65 78 65 } //1 windows\system\certifexpXP.exe
		$a_01_4 = {5c 77 69 6e 64 6f 77 73 5c 62 61 62 69 65 73 } //1 \windows\babies
		$a_01_5 = {5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 5c 77 33 32 75 70 64 2e 65 78 65 } //1 \WINDOWS\SYSTEM\w32upd.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=32
 
}