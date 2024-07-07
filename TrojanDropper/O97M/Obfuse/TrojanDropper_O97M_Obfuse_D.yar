
rule TrojanDropper_O97M_Obfuse_D{
	meta:
		description = "TrojanDropper:O97M/Obfuse.D,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {2e 43 72 65 61 74 65 20 22 66 6f 72 66 69 6c 65 73 20 2f 70 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 20 2f 6d 20 6e 6f 74 65 70 61 64 2e 65 78 65 20 2f 63 20 43 3a 5c 55 73 65 72 73 5c 75 73 65 72 5c 41 70 70 44 61 74 61 5c } //1 .Create "forfiles /p c:\windows\system32 /m notepad.exe /c C:\Users\user\AppData\
		$a_01_1 = {73 50 72 6f 63 20 3d 20 45 6e 76 69 72 6f 6e 28 22 77 69 6e 64 69 72 22 29 20 26 20 22 5c 5c 53 79 73 57 4f 57 36 34 5c 5c 72 75 6e 64 22 20 2b 20 22 6c 6c 33 32 2e 65 78 65 22 } //1 sProc = Environ("windir") & "\\SysWOW64\\rund" + "ll32.exe"
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}