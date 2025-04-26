
rule Backdoor_Win32_Akbot_B{
	meta:
		description = "Backdoor:Win32/Akbot.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6e 6f 70 65 2e 64 6c 6c 00 73 74 61 72 74 00 } //1
		$a_00_1 = {50 43 20 4e 45 54 57 4f 52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30 } //1 PC NETWORK PROGRAM 1.0
		$a_01_2 = {4c 41 4e 4d 41 4e 31 2e 30 } //1 LANMAN1.0
		$a_01_3 = {57 69 6e 64 6f 77 73 20 66 6f 72 20 57 6f 72 6b 67 72 6f 75 70 73 20 33 2e 31 61 } //1 Windows for Workgroups 3.1a
		$a_01_4 = {43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 43 41 } //1 CACACACACACACACACACACACACACACA
		$a_00_5 = {4c 41 4e 4d 41 4e 32 2e 31 } //1 LANMAN2.1
		$a_01_6 = {4e 54 20 4c 4d 20 30 2e 31 32 } //1 NT LM 0.12
		$a_01_7 = {53 4d 42 73 } //1 SMBs
		$a_01_8 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_9 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}