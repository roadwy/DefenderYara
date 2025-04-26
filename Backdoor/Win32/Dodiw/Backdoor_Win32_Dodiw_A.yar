
rule Backdoor_Win32_Dodiw_A{
	meta:
		description = "Backdoor:Win32/Dodiw.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 00 6f 00 53 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 2e 00 2e 00 2e 00 } //1 DoS Active...
		$a_01_1 = {46 00 69 00 6c 00 65 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 64 00 20 00 61 00 6e 00 64 00 20 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 64 00 } //1 File Downloaded and Executed
		$a_01_2 = {42 00 61 00 62 00 79 00 6c 00 6f 00 6e 00 20 00 52 00 41 00 54 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Babylon RAT Client
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}