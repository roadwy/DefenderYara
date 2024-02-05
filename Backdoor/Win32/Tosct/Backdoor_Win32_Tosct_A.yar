
rule Backdoor_Win32_Tosct_A{
	meta:
		description = "Backdoor:Win32/Tosct.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 32 33 34 35 00 00 00 31 32 33 21 40 23 71 77 65 51 57 45 } //01 00 
		$a_01_1 = {69 6e 69 65 74 2e 65 78 65 00 00 00 25 73 5c 25 73 00 00 00 63 6d 64 2e 65 78 65 00 43 72 65 61 74 65 50 69 70 65 } //00 00 
	condition:
		any of ($a_*)
 
}