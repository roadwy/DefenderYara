
rule Worm_Win32_Autorun_IB{
	meta:
		description = "Worm:Win32/Autorun.IB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 6e 65 78 74 68 6f 6f 6b 65 78 } //1 callnexthookex
		$a_01_1 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 autorun.inf
		$a_01_2 = {49 45 46 72 61 6d 65 } //1 IEFrame
		$a_01_3 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 61 2e 65 78 65 20 65 } //1 shell\Auto\command=a.exe e
		$a_01_4 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 61 2e 65 78 65 } //1 c:\windows\system32\a.exe
		$a_01_5 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 50 72 6f 6a 65 63 74 31 5f 61 75 74 6f 72 75 6e 2e 65 78 65 } //1 c:\windows\system32\Project1_autorun.exe
		$a_01_6 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 49 43 4c 2e 65 78 65 } //1 c:\windows\system32\ICL.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}