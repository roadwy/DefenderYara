
rule Worm_Win32_Autorun_EV{
	meta:
		description = "Worm:Win32/Autorun.EV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 20 66 6c 61 73 68 69 6e 66 2e 64 6c 6c 20 4d 73 67 00 00 00 ff ff ff ff 04 00 00 00 6f 70 65 6e 00 00 00 00 ff ff ff ff 07 00 00 00 41 75 74 6f 52 75 6e 00 ff ff ff ff 0c 00 00 00 73 68 65 6c 6c 65 78 65 63 75 74 65 00 00 00 00 ff ff ff ff 12 00 00 00 73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 00 00 ff ff ff ff 12 00 00 00 73 68 65 6c 6c 5c 4f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 00 00 ff ff ff ff 12 00 00 00 73 68 65 6c 6c 5c 46 69 6e 64 5c 63 6f 6d 6d 61 } //1
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_2 = {64 6f 6c 70 68 69 6e 36 31 2e 64 6c 6c 20 4d 73 67 53 74 61 72 74 } //1 dolphin61.dll MsgStart
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Worm_Win32_Autorun_EV_2{
	meta:
		description = "Worm:Win32/Autorun.EV,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {67 6f 74 6f 20 73 65 6c 66 6b 69 6c 6c } //1 goto selfkill
		$a_01_1 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_01_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_4 = {35 35 37 42 39 30 33 38 2d 46 43 38 37 2d 34 35 33 43 2d 38 42 30 38 2d 33 32 44 38 35 46 34 36 45 41 43 34 } //1 557B9038-FC87-453C-8B08-32D85F46EAC4
		$a_01_5 = {41 70 72 6f 6e 5f 52 75 6e } //1 Apron_Run
		$a_01_6 = {49 45 5f 48 49 44 45 5f 52 75 6e } //1 IE_HIDE_Run
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 65 74 77 61 6e 67 2e 63 6f 6d } //1 http://www.netwang.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}