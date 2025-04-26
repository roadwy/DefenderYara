
rule Backdoor_Win32_Ginwui_E{
	meta:
		description = "Backdoor:Win32/Ginwui.E,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_00_0 = {56 57 50 e8 03 00 00 00 e9 eb 04 58 40 50 c3 } //10
		$a_01_1 = {41 70 70 49 6e 69 74 5f 44 4c 4c 73 } //1 AppInit_DLLs
		$a_01_2 = {25 73 5c 64 72 69 76 65 72 73 5c 25 73 } //1 %s\drivers\%s
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {47 55 49 53 76 72 44 6c 6c 2e 64 6c 6c 00 44 6f 48 6f 6f 6b 00 44 6f 54 65 73 74 } //1
		$a_01_5 = {57 49 4e 47 55 49 53 } //1 WINGUIS
		$a_01_6 = {5c 47 55 49 53 76 72 44 6c 6c 5c 52 65 6c 65 61 73 65 5c 47 55 49 53 76 72 44 6c 6c 2e 70 64 62 } //1 \GUISvrDll\Release\GUISvrDll.pdb
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=15
 
}