
rule PWS_Win32_QQpass_DI{
	meta:
		description = "PWS:Win32/QQpass.DI,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 0c 00 00 "
		
	strings :
		$a_80_0 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 57 69 6e 52 61 52 2e 65 78 65 } //%SystemRoot%\WinRaR.exe  1
		$a_80_1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 77 69 6e 6c 6f 67 6f 72 2e 65 78 65 } //%SystemRoot%\winlogor.exe  1
		$a_80_2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 69 6e 74 65 6e 74 2e 65 78 65 } //%SystemRoot%\intent.exe  1
		$a_80_3 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 6f 75 72 72 6f 2e 65 78 65 } //%SystemRoot%\sourro.exe  1
		$a_80_4 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 77 69 6e 61 64 72 2e 65 78 65 } //%SystemRoot%\winadr.exe  1
		$a_80_5 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 77 69 6e 6e 74 2e 65 78 65 } //%SystemRoot%\winnt.exe  1
		$a_80_6 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 56 63 68 6f 6e 74 2e 65 78 65 } //%SystemRoot%\SVchont.exe  1
		$a_01_7 = {48 6f 6f 6b 4f 6e } //1 HookOn
		$a_01_8 = {48 6f 6f 6b 4f 66 66 } //1 HookOff
		$a_01_9 = {53 74 61 72 74 48 6f 6f 6b } //1 StartHook
		$a_00_10 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_00_11 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=11
 
}