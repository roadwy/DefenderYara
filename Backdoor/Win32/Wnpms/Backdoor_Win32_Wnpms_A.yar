
rule Backdoor_Win32_Wnpms_A{
	meta:
		description = "Backdoor:Win32/Wnpms.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 73 64 6f 77 6e 6c 6f 61 64 65 72 00 20 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 77 6e 70 6d 73 2e 65 78 65 } //01 00 
		$a_01_1 = {5f 77 69 6e 33 32 5f 5f 77 6e 70 6d 73 5f 73 6d 5f 5f } //01 00  _win32__wnpms_sm__
		$a_01_2 = {5f 5f 77 69 6e 33 32 5f 5f 77 6e 70 6d 73 5f 73 64 6d 5f 5f } //02 00  __win32__wnpms_sdm__
		$a_01_3 = {6d 79 20 70 6f 72 74 20 5b 25 69 5d 0a 00 64 65 70 2e 6d 76 6c 30 61 6e 37 2e 63 6f 6d 00 61 75 74 68 6f 72 69 7a 65 64 20 49 50 } //00 00 
	condition:
		any of ($a_*)
 
}