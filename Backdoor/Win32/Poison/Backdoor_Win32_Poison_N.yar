
rule Backdoor_Win32_Poison_N{
	meta:
		description = "Backdoor:Win32/Poison.N,SIGNATURE_TYPE_PEHSTR,ffffff8c 00 ffffff8c 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 33 f6 8d 46 01 bf ff 00 00 00 99 f7 ff 30 13 43 46 49 75 } //100
		$a_01_1 = {53 74 61 72 74 53 65 72 76 69 63 65 41 } //10 StartServiceA
		$a_01_2 = {63 6d 64 20 2f 63 20 64 65 6c 20 43 3a 5c 6d 79 61 70 70 2e 65 78 65 } //10 cmd /c del C:\myapp.exe
		$a_01_3 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //10 %SystemRoot%\system32\svchost.exe -k netsvcs
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //10 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=140
 
}