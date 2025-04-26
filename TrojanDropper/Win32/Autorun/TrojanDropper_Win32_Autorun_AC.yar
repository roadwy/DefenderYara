
rule TrojanDropper_Win32_Autorun_AC{
	meta:
		description = "TrojanDropper:Win32/Autorun.AC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 20 61 64 64 20 25 63 61 6d 62 6f 64 69 61 25 20 48 69 64 64 65 6e 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 20 2f 66 } //1 reg add %cambodia% Hidden /t REG_DWORD /d 0 /f
		$a_01_1 = {63 6f 70 79 20 25 30 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 2e 65 78 65 20 2f 79 } //1 copy %0 %windir%\system32.exe /y
		$a_01_2 = {65 63 68 6f 20 5b 61 75 74 6f 72 75 6e 5d 3e 3e 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 5c 64 72 76 65 72 2e 63 61 62 2e 73 79 73 } //1 echo [autorun]>>%windir%\system\drver.cab.sys
		$a_01_3 = {25 64 72 69 76 65 25 20 6d 64 20 25 25 78 3a 5c 53 6f 75 6e 64 73 } //1 %drive% md %%x:\Sounds
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}