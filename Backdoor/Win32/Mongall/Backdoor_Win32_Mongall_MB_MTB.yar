
rule Backdoor_Win32_Mongall_MB_MTB{
	meta:
		description = "Backdoor:Win32/Mongall.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 84 24 44 01 00 00 83 e1 03 52 f3 a4 50 ff 15 } //1
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6e 65 74 62 72 69 64 67 65 2e 65 78 65 } //1 \WINDOWS\SYSTEM32\netbridge.exe
		$a_01_3 = {6e 64 62 73 73 68 2e 63 6f 6d } //1 ndbssh.com
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}