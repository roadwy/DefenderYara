
rule PWS_Win32_Zengtu_B{
	meta:
		description = "PWS:Win32/Zengtu.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 09 00 0b 00 00 "
		
	strings :
		$a_00_0 = {57 68 42 6f 79 } //2 WhBoy
		$a_00_1 = {5a 68 65 6e 67 54 75 } //2 ZhengTu
		$a_01_2 = {6d 61 69 6c 62 6f 64 79 3d } //2 mailbody=
		$a_00_3 = {60 75 75 70 32 2e 2e } //2 `uup2..
		$a_00_4 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a } //2 Content-Type:
		$a_01_5 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_6 = {4d 75 74 65 78 } //1 Mutex
		$a_00_7 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_8 = {48 6f 6f 6b 4f 6e } //1 HookOn
		$a_00_9 = {67 67 73 61 66 65 2e 63 6f 6d 2f 67 67 74 6f 6f 6c 73 2e 69 6e 69 } //65521 ggsafe.com/ggtools.ini
		$a_00_10 = {75 70 64 61 74 65 2e 67 67 73 61 66 65 2e 63 6f 6d 2f } //65521 update.ggsafe.com/
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*65521+(#a_00_10  & 1)*65521) >=9
 
}