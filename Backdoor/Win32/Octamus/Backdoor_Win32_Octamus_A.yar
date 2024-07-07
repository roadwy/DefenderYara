
rule Backdoor_Win32_Octamus_A{
	meta:
		description = "Backdoor:Win32/Octamus.A,SIGNATURE_TYPE_PEHSTR,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {4f 70 61 63 74 69 75 6d 73 20 42 6f 74 } //10 Opactiums Bot
		$a_01_1 = {53 74 6f 70 70 65 64 20 66 6c 6f 6f 64 69 6e 67 2e 2e 2e 77 61 69 74 69 6e 67 20 6e 6f 77 20 66 6f 72 20 63 6f 6d 6d 61 6e 64 73 2e } //1 Stopped flooding...waiting now for commands.
		$a_01_2 = {50 72 6f 62 6c 65 6d 73 20 77 68 69 6c 65 20 6b 69 6c 6c 69 6e 67 20 74 68 65 20 42 6f 74 } //1 Problems while killing the Bot
		$a_01_3 = {6b 69 6c 6c 66 69 72 65 77 61 6c 6c 73 } //1 killfirewalls
		$a_01_4 = {73 79 73 66 75 63 6b } //1 sysfuck
		$a_01_5 = {74 6d 72 6b 69 6c 6c 64 65 76 69 6c 74 68 69 6e 67 73 } //1 tmrkilldevilthings
		$a_01_6 = {70 69 6e 67 20 31 31 31 2e 31 31 31 2e 31 31 31 2e 31 31 31 } //1 ping 111.111.111.111
		$a_01_7 = {57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 72 75 6e 2e 62 61 74 } //1 WINDOWS\system32\run.bat
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=16
 
}