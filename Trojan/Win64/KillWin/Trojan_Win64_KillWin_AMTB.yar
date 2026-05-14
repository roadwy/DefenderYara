
rule Trojan_Win64_KillWin_AMTB{
	meta:
		description = "Trojan:Win64/KillWin!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 74 68 65 20 43 75 74 65 20 43 61 74 20 76 69 72 75 73 21 } //Your computer has been infected with the Cute Cat virus!  1
		$a_80_1 = {64 65 6c 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 2a 2e 2a 20 2f 66 20 2f 73 20 2f 71 } //del C:\Windows\System32\*.* /f /s /q  1
		$a_80_2 = {4d 79 20 41 70 70 20 53 74 61 72 74 75 70 20 53 68 6f 72 74 63 75 74 } //My App Startup Shortcut  1
		$a_80_3 = {72 65 67 20 61 64 64 20 22 48 4b 4c 4d 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 22 20 2f 76 20 22 53 63 61 6e 63 6f 64 65 20 4d 61 70 22 20 2f 74 20 52 45 47 5f 42 49 4e 41 52 59 20 2f 64 } //reg add "HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout" /v "Scancode Map" /t REG_BINARY /d  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}