
rule Adware_Win32_Enumerate{
	meta:
		description = "Adware:Win32/Enumerate,SIGNATURE_TYPE_PEHSTR,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 65 6e 75 6d 65 72 61 74 65 5f 67 74 } //01 00 
		$a_01_1 = {65 6e 75 6d 73 74 61 74 65 2e 63 6f 2e 6b 72 } //01 00 
		$a_01_2 = {74 6f 70 73 65 61 72 63 68 2e 65 6e 75 6d 65 72 61 74 65 2e 63 6f 2e 6b 72 } //01 00 
		$a_01_3 = {65 6e 75 6d 73 74 5c 72 65 6c 65 61 73 65 5c 65 6e 75 6d 73 74 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}