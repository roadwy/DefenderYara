
rule Backdoor_Win32_Bifrose_gen_A{
	meta:
		description = "Backdoor:Win32/Bifrose.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 09 00 00 "
		
	strings :
		$a_00_0 = {55 8b ec 56 33 f6 39 75 0c 7e 1b 8b 45 08 33 d2 8d 0c 06 8b c6 f7 75 14 8b 45 10 8a 04 02 30 01 46 3b 75 0c 7c e5 5e 5d c3 } //3
		$a_00_1 = {6b 69 78 4b 7a 6d 69 7c 6d 4b 69 78 7c 7d 7a 6d 5f 71 76 6c 77 7f 49 } //2
		$a_00_2 = {4d 76 69 6a 74 6d 49 7d 7c 77 6c 71 69 74 } //2 MvijtmI}|wlqit
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 57 47 65 74 00 } //1 体呆䅗䕒坜敇t
		$a_00_5 = {73 74 75 62 70 61 74 68 00 } //1
		$a_00_6 = {70 6c 75 67 69 6e 31 2e 64 61 74 00 } //1 汰杵湩⸱慤t
		$a_01_7 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41 } //1 capCreateCaptureWindowA
		$a_01_8 = {25 63 25 64 2e 25 64 2e 25 64 2e 25 64 7c 25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 75 7c 25 69 7c 25 69 7c 25 75 7c } //1 %c%d.%d.%d.%d|%s|%s|%s|%s|%s|%u|%i|%i|%u|
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=6
 
}