
rule Trojan_Win32_ModiLoader_ARA_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {6d 6b 64 69 72 20 22 5c 5c 3f 5c 43 3a 5c 57 69 6e 64 6f 77 73 20 5c 53 79 73 74 65 6d 33 32 22 } //2 mkdir "\\?\C:\Windows \System32"
		$a_01_1 = {45 43 48 4f 20 46 7c 78 63 6f 70 79 } //2 ECHO F|xcopy
		$a_01_2 = {22 43 3a 5c 57 69 6e 64 6f 77 73 20 5c 53 79 73 74 65 6d 33 32 5c 22 20 2f 4b 20 2f 44 20 2f 48 20 2f 59 } //2 "C:\Windows \System32\" /K /D /H /Y
		$a_01_3 = {22 65 61 73 69 6e 76 6f 6b 65 72 2e 65 78 65 22 } //2 "easinvoker.exe"
		$a_01_4 = {22 6e 65 74 75 74 69 6c 73 2e 64 6c 6c 22 } //2 "netutils.dll"
		$a_01_5 = {22 4b 44 45 43 4f 2e 62 61 74 22 } //2 "KDECO.bat"
		$a_01_6 = {22 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 27 43 3a 5c 55 73 65 72 73 27 22 } //2 "Add-MpPreference -ExclusionPath 'C:\Users'"
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}