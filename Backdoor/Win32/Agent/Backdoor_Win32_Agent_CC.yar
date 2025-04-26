
rule Backdoor_Win32_Agent_CC{
	meta:
		description = "Backdoor:Win32/Agent.CC,SIGNATURE_TYPE_PEHSTR,2b 00 2b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {5b 4e 75 6d 20 4c 6f 63 6b 5d } //10 [Num Lock]
		$a_01_1 = {5b 44 6f 77 6e 5d } //10 [Down]
		$a_01_2 = {5b 52 69 67 68 74 5d } //10 [Right]
		$a_01_3 = {5b 55 50 5d } //10 [UP]
		$a_01_4 = {43 68 65 63 6b 20 43 6c 6f 6e 65 20 41 63 63 6f 75 6e 74 } //1 Check Clone Account
		$a_01_5 = {58 53 68 65 6c 6c 20 42 61 63 6b 44 6f 6f 72 } //1 XShell BackDoor
		$a_01_6 = {61 72 70 73 70 6f 6f 66 } //1 arpspoof
		$a_01_7 = {4f 6e 6c 69 6e 65 20 4b 65 79 4c 6f 67 } //1 Online KeyLog
		$a_01_8 = {43 6c 6f 6e 65 20 55 73 65 72 20 41 73 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //1 Clone User As Administrator
		$a_01_9 = {2d 73 6e 69 66 66 70 77 64 } //1 -sniffpwd
		$a_01_10 = {72 65 73 65 74 5f 73 70 6f 6f 66 5f 73 6f 63 6b } //1 reset_spoof_sock
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=43
 
}