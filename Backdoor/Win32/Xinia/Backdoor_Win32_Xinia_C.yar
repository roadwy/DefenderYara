
rule Backdoor_Win32_Xinia_C{
	meta:
		description = "Backdoor:Win32/Xinia.C,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 44 72 69 76 65 72 73 5c 62 65 65 70 2e 73 79 73 } //2 C:\WINDOWS\system32\Drivers\beep.sys
		$a_00_1 = {5c 64 70 76 73 6f 63 6b 65 74 2e 64 6c 6c } //2 \dpvsocket.dll
		$a_00_2 = {5c 66 69 6c 65 70 61 67 65 73 2e 73 79 73 } //2 \filepages.sys
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 4d 61 72 6b 73 20 49 6e 66 6f 5c } //2 SOFTWARE\Microsoft\Windows\Marks Info\
		$a_01_4 = {8b 1d 08 80 40 00 51 8d 8c 24 40 02 00 00 51 6a 01 50 68 28 93 40 00 52 ff d3 8d bc 24 3c 01 00 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_01_4  & 1)*1) >=8
 
}