
rule Backdoor_Win32_Fsit_A{
	meta:
		description = "Backdoor:Win32/Fsit.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 43 2b 2b 20 52 75 6e 74 69 6d 65 20 4c 69 62 72 61 72 79 } //1 Microsoft Visual C++ Runtime Library
		$a_01_1 = {63 6f 6d 6d 61 6e 64 2e 63 6f 6d } //1 command.com
		$a_01_2 = {66 73 68 69 74 2e 73 65 6c 66 69 70 2e 63 6f 6d 2f 7e 66 73 6f 63 6b 31 2f 67 6f 64 2e 70 68 70 } //1 fshit.selfip.com/~fsock1/god.php
		$a_01_3 = {2e 70 68 70 3f 70 69 70 3d } //1 .php?pip=
		$a_01_4 = {43 72 65 61 74 65 4d 75 74 65 78 41 } //1 CreateMutexA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_6 = {49 6e 74 65 72 6e 65 74 43 6c 6f 73 65 48 61 6e 64 6c 65 } //1 InternetCloseHandle
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}