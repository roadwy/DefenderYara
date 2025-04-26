
rule TrojanSpy_Win32_Utohoki_A{
	meta:
		description = "TrojanSpy:Win32/Utohoki.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {23 49 6e 73 74 61 6c 6c 4b 65 79 62 64 48 6f 6f 6b } //1 #InstallKeybdHook
		$a_01_1 = {23 49 6e 73 74 61 6c 6c 4d 6f 75 73 65 48 6f 6f 6b } //1 #InstallMouseHook
		$a_01_2 = {46 69 6c 65 43 6f 70 79 2c 25 41 5f 53 63 72 69 70 74 46 75 6c 6c 50 61 74 68 25 2c 25 41 5f 41 70 70 44 61 74 61 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 63 74 66 6d 6f 6e 2e 65 78 65 } //1 FileCopy,%A_ScriptFullPath%,%A_AppData%\Microsoft\Office\ctfmon.exe
		$a_01_3 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 2c 4d 69 63 72 6f 73 6f 66 74 20 54 65 78 74 20 53 65 72 76 69 63 65 73 2c 25 41 5f 41 70 70 44 61 74 61 25 5c } //1 \CurrentVersion\Run,Microsoft Text Services,%A_AppData%\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}