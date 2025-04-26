
rule Backdoor_Win32_Afcore_gen_A{
	meta:
		description = "Backdoor:Win32/Afcore.gen!A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 46 43 4f 52 45 } //1 AFCORE
		$a_01_1 = {4f 63 74 6f 70 75 73 20 68 61 73 20 62 65 65 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 73 70 61 77 6e 65 64 20 28 50 49 44 3a 20 25 64 29 } //1 Octopus has been successfully spawned (PID: %d)
		$a_01_2 = {73 68 75 74 64 6f 77 6e 20 72 65 71 75 65 73 74 20 66 72 6f 6d 20 73 65 72 76 69 63 65 20 63 6f 6e 74 72 6f 6c 20 68 61 6e 64 6c 65 72 } //1 shutdown request from service control handler
		$a_01_3 = {41 63 63 65 70 74 69 6e 67 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 66 72 6f 6d 20 25 61 } //1 Accepting connection from %a
		$a_01_4 = {44 49 53 4b 46 4c 4f 4f 44 } //1 DISKFLOOD
		$a_01_5 = {46 6c 6f 6f 64 69 6e 67 20 6f 66 20 25 73 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 6c 65 74 65 64 } //1 Flooding of %s has been completed
		$a_01_6 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 GetClipboardData
		$a_01_7 = {50 6f 73 74 4d 65 73 73 61 67 65 41 } //1 PostMessageA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}