
rule Trojan_Win32_Kovter_I{
	meta:
		description = "Trojan:Win32/Kovter.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {8a 54 32 ff 80 e2 0f 32 c2 88 45 f3 } //1
		$a_03_1 = {33 c0 8a 03 ba 02 00 00 00 e8 90 01 04 8b 55 90 01 01 8b c7 e8 90 01 04 43 4e 75 e1 90 00 } //1
		$a_01_2 = {3d 6e 65 77 25 32 30 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 3b 00 } //1
		$a_01_3 = {69 74 63 6f 5c 69 6e 66 65 63 74 5c 62 69 6e } //1 itco\infect\bin
		$a_01_4 = {69 66 20 65 78 69 73 74 20 22 25 53 22 20 67 6f 74 6f 20 3a 52 45 44 4f } //1 if exist "%S" goto :REDO
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}
rule Trojan_Win32_Kovter_I_2{
	meta:
		description = "Trojan:Win32/Kovter.I,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 DisableRealtimeMonitoring
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 57 6f 77 36 34 33 32 4e 6f 64 65 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 52 65 61 6c 2d 54 69 6d 65 20 50 72 6f 74 65 63 74 69 6f 6e } //1 SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection
		$a_00_2 = {4e 6f 41 75 74 6f 55 70 64 61 74 65 } //1 NoAutoUpdate
		$a_00_3 = {25 73 5c 25 73 2e 68 74 61 } //1 %s\%s.hta
		$a_00_4 = {6b 69 6c 6c 61 6c 6c } //1 killall
		$a_03_5 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 90 02 20 2e 68 74 61 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}