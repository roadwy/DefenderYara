
rule Backdoor_Win32_Scom{
	meta:
		description = "Backdoor:Win32/Scom,SIGNATURE_TYPE_PEHSTR,21 00 21 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 53 43 6f 6d } //10 Software\SCom
		$a_01_1 = {70 68 6f 6e 65 47 65 74 48 6f 6f 6b 53 77 69 74 63 68 } //10 phoneGetHookSwitch
		$a_01_2 = {6c 69 6e 65 55 6e 63 6f 6d 70 6c 65 74 65 43 61 6c 6c } //10 lineUncompleteCall
		$a_01_3 = {2f 64 6f 6e 74 64 69 61 6c 20 2f 6e 6f 63 6f 6e 6e 65 63 74 } //1 /dontdial /noconnect
		$a_01_4 = {77 69 6e 64 6f 77 73 5c 25 73 2e 65 78 65 20 2f 64 6f 6e 74 64 69 61 6c 20 2f 64 65 6c 61 79 6c 6f 61 64 20 2f 69 6e 73 74 61 6c 6c } //1 windows\%s.exe /dontdial /delayload /install
		$a_01_5 = {2f 64 70 6e 32 20 00 00 00 00 00 00 55 44 50 4e 5f 4e 4f 55 49 00 00 00 2f 64 69 61 6c 6e 64 73 } //1
		$a_01_6 = {2f 63 6e 74 6e 6f 77 20 00 00 00 00 2f 68 61 6e 67 75 70 20 00 00 00 00 56 45 4e 44 4f 52 49 44 3a } //1
		$a_01_7 = {64 69 73 70 6c 61 79 64 69 61 6c 75 70 2e 6a 68 74 6d 6c } //1 displaydialup.jhtml
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=33
 
}