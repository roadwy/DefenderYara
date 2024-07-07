
rule TrojanDropper_Win32_Farfli_D{
	meta:
		description = "TrojanDropper:Win32/Farfli.D,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
		$a_01_1 = {33 36 25 78 73 76 63 } //2 36%xsvc
		$a_01_2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //3 %SystemRoot%\System32\svchost.exe -k netsvcs
		$a_01_3 = {55 5d 90 90 41 49 90 90 90 90 41 49 90 41 49 80 3e 00 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4) >=10
 
}