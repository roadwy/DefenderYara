
rule Backdoor_Win32_Ecltys_A{
	meta:
		description = "Backdoor:Win32/Ecltys.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 2f 63 6c 61 73 73 69 63 2f 61 63 6f 75 6e 74 2f 69 6d 61 67 65 2f 61 64 64 72 5f 6d 65 6d 62 65 72 2e 61 73 70 } //01 00 
		$a_01_1 = {00 5c 5c 2e 5c 70 69 70 65 5c 73 73 6e 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}