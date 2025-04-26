
rule TrojanProxy_Win32_Wopla_Z{
	meta:
		description = "TrojanProxy:Win32/Wopla.Z,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //1 Microsoft Visual C++ Runtime Library
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 59 4c 6f 61 64 5c 76 61 72 73 } //1 Software\Microsoft\YLoad\vars
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_3 = {6c 61 6d 6f 64 61 6e 6f 2e 69 6e 66 6f 2f 61 66 66 2d 6c 69 67 68 74 } //1 lamodano.info/aff-light
		$a_00_4 = {47 65 74 53 79 73 74 65 6d 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //1 GetSystemWindowsDirectoryA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}