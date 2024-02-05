
rule Backdoor_Win32_Xifos_C{
	meta:
		description = "Backdoor:Win32/Xifos.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 68 65 71 75 69 63 6b 62 72 6f 77 6e 66 78 6a 6d 70 73 76 61 6c 7a 79 64 67 } //01 00 
		$a_01_1 = {3c 50 53 4d 3e 59 65 70 2c 20 25 73 20 69 73 20 68 65 72 65 2e 3c 2f 50 53 4d 3e } //01 00 
		$a_01_2 = {3c 4d 61 63 68 69 6e 65 47 75 69 64 3e 25 73 3c 2f 4d 61 63 68 69 6e 65 47 75 69 64 3e } //01 00 
		$a_01_3 = {6a 6f 68 61 6e 73 73 6f 6e 2e 73 63 61 72 6c 65 74 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}