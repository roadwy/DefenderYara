
rule Backdoor_Win32_Polnur_A{
	meta:
		description = "Backdoor:Win32/Polnur.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 6e 74 65 6c 43 6f 6e 74 72 6f 6c 6c 65 72 } //01 00  IntelController
		$a_01_1 = {4d 61 6e 61 67 65 72 5f 52 75 6e 5f 4c 6f 6f 70 00 00 00 00 45 78 70 5f 4f 6e 52 65 61 64 } //01 00 
		$a_00_2 = {7e 4d 48 7a } //01 00  ~MHz
		$a_00_3 = {63 5f 31 31 30 32 2e 6e 6c 73 } //01 00  c_1102.nls
		$a_01_4 = {53 74 61 72 74 46 75 6e 00 00 00 00 53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}