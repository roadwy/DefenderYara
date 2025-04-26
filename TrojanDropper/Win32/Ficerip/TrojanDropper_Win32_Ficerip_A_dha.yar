
rule TrojanDropper_Win32_Ficerip_A_dha{
	meta:
		description = "TrojanDropper:Win32/Ficerip.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 2f 00 42 00 20 00 2f 00 2f 00 4e 00 6f 00 6c 00 6f 00 67 00 6f 00 20 00 2f 00 2f 00 45 00 3a 00 4a 00 53 00 63 00 72 00 69 00 70 00 74 00 } //1 WScript.exe //B //Nologo //E:JScript
		$a_01_1 = {4d 53 4f 66 66 69 63 65 4d 75 74 65 78 } //1 MSOfficeMutex
		$a_01_2 = {77 69 6e 33 32 6b 66 75 6c 6c 2e 73 79 73 } //1 win32kfull.sys
		$a_01_3 = {5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 4f 00 6e 00 63 00 65 00 } //1 \Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_4 = {45 78 65 63 00 50 45 00 } //1 硅捥倀E
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}