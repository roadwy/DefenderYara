
rule TrojanSpy_Win32_Swisyn_A{
	meta:
		description = "TrojanSpy:Win32/Swisyn.A,SIGNATURE_TYPE_PEHSTR,10 00 10 00 16 00 00 "
		
	strings :
		$a_01_0 = {25 41 50 50 44 41 54 41 25 5c 52 6f 61 6d 69 6e 67 5c 64 6c 6c 68 6f 73 74 2e 65 78 65 } //3 %APPDATA%\Roaming\dllhost.exe
		$a_01_1 = {73 79 73 74 65 6d 2e 62 61 74 } //3 system.bat
		$a_01_2 = {6e 74 6c 6f 67 2e 73 79 73 } //3 ntlog.sys
		$a_01_3 = {63 6d 64 20 2f 63 20 52 45 47 20 41 44 44 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //2 cmd /c REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_4 = {63 6d 64 20 2f 63 20 52 45 47 20 41 44 44 20 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 cmd /c REG ADD HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {2f 56 20 44 4c 4c 48 6f 73 74 20 2f 44 } //1 /V DLLHost /D
		$a_01_6 = {2f 56 20 53 68 65 6c 6c 20 2f 44 } //1 /V Shell /D
		$a_01_7 = {5b 41 73 61 67 69 4f 4b 5d } //1 [AsagiOK]
		$a_01_8 = {5b 59 75 6b 61 72 69 4f 4b 5d } //1 [YukariOK]
		$a_01_9 = {5b 53 61 67 4f 4b 5d } //1 [SagOK]
		$a_01_10 = {5b 42 61 73 6c 61 74 5d } //1 [Baslat]
		$a_01_11 = {5b 42 61 63 6b 73 70 61 63 65 5d } //1 [Backspace]
		$a_01_12 = {5b 44 65 6c 5d } //1 [Del]
		$a_01_13 = {5b 54 61 62 5d } //1 [Tab]
		$a_01_14 = {5b 45 73 63 5d } //1 [Esc]
		$a_01_15 = {5b 43 61 70 73 4c 6f 63 6b 5d } //1 [CapsLock]
		$a_01_16 = {5b 43 6c 65 61 72 5d } //1 [Clear]
		$a_01_17 = {5b 50 47 55 50 5d } //1 [PGUP]
		$a_01_18 = {5b 53 68 69 66 74 5d } //1 [Shift]
		$a_01_19 = {5b 43 74 72 6c 5d } //1 [Ctrl]
		$a_01_20 = {5b 41 6c 74 5d } //1 [Alt]
		$a_01_21 = {5b 43 6c 69 70 62 6f 61 72 64 5d } //1 [Clipboard]
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1) >=16
 
}
rule TrojanSpy_Win32_Swisyn_A_2{
	meta:
		description = "TrojanSpy:Win32/Swisyn.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_00_0 = {6e 74 6c 6f 67 2e 73 79 73 } //1 ntlog.sys
		$a_00_1 = {6e 74 63 6f 6d 2e 64 6c 6c } //1 ntcom.dll
		$a_00_2 = {68 61 7a 69 72 6c 61 } //1 hazirla
		$a_00_3 = {75 73 65 72 3d } //1 user=
		$a_00_4 = {64 65 73 74 69 6e 6f 3d } //1 destino=
		$a_00_5 = {63 6f 6e 74 65 75 64 6f 3d } //1 conteudo=
		$a_00_6 = {45 72 72 6f 72 20 6f 6e 20 46 46 46 46 46 46 46 46 46 } //1 Error on FFFFFFFFF
		$a_00_7 = {00 2f 31 73 74 65 6d 00 } //1 ⼀猱整m
		$a_00_8 = {00 6c 2e 70 68 70 00 } //1
		$a_03_9 = {ff b5 c8 fe ff ff 68 ?? ?? ?? ?? ff b5 ec fe ff ff ff b5 ec fe ff ff ff b5 ec fe ff ff 68 ?? ?? ?? ?? ff b5 d0 fe ff ff ff b5 d4 fe ff ff ff b5 d0 fe ff ff ff b5 d0 fe ff ff ff b5 d8 fe ff ff 68 ?? ?? ?? ?? ff b5 cc fe ff ff ff b5 dc fe ff ff ff b5 e4 fe ff ff ff b5 e0 fe ff ff 68 ?? ?? ?? ?? ff b5 f4 fe ff ff ff b5 cc fe ff ff 68 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_03_9  & 1)*3) >=7
 
}