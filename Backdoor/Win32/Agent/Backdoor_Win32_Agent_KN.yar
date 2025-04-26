
rule Backdoor_Win32_Agent_KN{
	meta:
		description = "Backdoor:Win32/Agent.KN,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {53 74 61 72 74 20 44 6f 77 6e 6c 6f 61 64 20 61 6e 64 20 72 75 6e 20 74 61 73 6b } //1 Start Download and run task
		$a_01_2 = {43 6f 6d 70 6c 65 74 65 20 44 6f 77 6e 6c 6f 61 64 20 61 6e 64 20 72 75 6e 20 74 61 73 6b } //1 Complete Download and run task
		$a_01_3 = {43 6c 6f 6e 65 73 5c 56 49 53 54 41 5c 76 69 73 74 61 5c 72 65 6c 65 61 73 65 5c 56 69 73 74 61 2e 70 64 62 } //1 Clones\VISTA\vista\release\Vista.pdb
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_01_5 = {35 45 39 37 35 35 41 31 2d 33 31 34 41 2d 34 61 65 36 2d 39 39 45 31 2d 42 39 46 37 44 43 37 43 37 43 46 30 } //1 5E9755A1-314A-4ae6-99E1-B9F7DC7C7CF0
		$a_01_6 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_7 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_8 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //1 HttpSendRequestA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}