
rule Backdoor_Win32_Prorat_AN{
	meta:
		description = "Backdoor:Win32/Prorat.AN,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 65 74 57 69 6e 64 6f 77 54 65 78 74 41 } //01 00  GetWindowTextA
		$a_01_1 = {73 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  setWindowsHookExA
		$a_01_2 = {00 00 01 00 02 00 68 6f 64 6c 6c 2e 64 6c 6c 00 4b 49 49 73 53 65 73 5f 5f 4d 63 61 66 45 65 00 4b 69 73 73 65 73 5f 54 6f 5f 54 72 6f 6a 61 6e 68 75 6e 74 65 72 00 69 6e 73 74 61 6c 6c 68 6f 6f 6b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 } //01 00 
		$a_01_3 = {5c 6b 74 64 33 32 2e 61 74 6d } //00 00  \ktd32.atm
	condition:
		any of ($a_*)
 
}