
rule PWS_Win32_Lmir_E_dll{
	meta:
		description = "PWS:Win32/Lmir.E!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 73 3f 73 6e 3d 25 73 26 75 6e 3d 25 73 26 70 77 3d 25 73 26 73 70 3d 25 73 26 70 6e 3d 25 73 26 67 64 31 3d 25 64 26 67 64 32 3d 25 64 } //1 %s?sn=%s&un=%s&pw=%s&sp=%s&pn=%s&gd1=%d&gd2=%d
		$a_01_1 = {5c 73 79 73 74 65 6d 33 32 5c 6d 79 77 69 6e 69 6e 65 74 31 30 30 2e 64 6c 6c } //1 \system32\mywininet100.dll
		$a_01_2 = {5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 69 6e 65 74 2e 64 6c 6c } //1 \system32\wininet.dll
		$a_01_3 = {5c 73 79 73 74 65 6d 33 32 5c 77 73 32 5f 33 32 2e 64 6c 6c } //1 \system32\ws2_32.dll
		$a_00_4 = {73 6f 75 6c 2e 65 78 65 } //1 soul.exe
		$a_01_5 = {57 69 6e 49 6e 65 74 } //1 WinInet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}