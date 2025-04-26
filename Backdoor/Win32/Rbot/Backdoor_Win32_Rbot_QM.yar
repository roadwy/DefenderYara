
rule Backdoor_Win32_Rbot_QM{
	meta:
		description = "Backdoor:Win32/Rbot.QM,SIGNATURE_TYPE_PEHSTR,05 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {5b 5a 59 45 58 45 43 5d } //1 [ZYEXEC]
		$a_01_1 = {5b 5a 59 4c 4f 41 44 5d } //1 [ZYLOAD]
		$a_01_2 = {5b 5a 59 53 48 45 4c 4c 5d } //1 [ZYSHELL]
		$a_01_3 = {7a 79 73 69 6e 66 6f 00 } //1 祺楳普o
		$a_01_4 = {7a 79 72 65 61 64 73 00 } //1 祺敲摡s
		$a_01_5 = {7a 79 62 6f 74 2e 6f 66 66 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}