
rule Backdoor_Win32_Dumadoor_A{
	meta:
		description = "Backdoor:Win32/Dumadoor.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 75 72 6c 2e 64 61 74 00 5c 64 76 70 64 2e 64 6c 6c 00 4d 48 6f 6f 6b 00 } //01 00 
		$a_01_1 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 6c 6f 61 64 33 32 00 53 6f 66 74 77 61 72 65 5c 53 41 52 53 5c 00 5c 6e 65 74 64 78 2e 64 61 74 } //01 00 
		$a_03_2 = {6d 61 69 6c 73 65 6e 64 65 64 00 90 01 01 00 5c 73 65 6e 64 5f 6c 6f 67 73 5f 74 72 69 67 67 65 72 00 5c 64 76 70 2e 6c 6f 67 90 00 } //01 00 
		$a_01_3 = {73 63 61 6d 5f 70 61 67 65 5f 75 72 6c } //00 00 
	condition:
		any of ($a_*)
 
}