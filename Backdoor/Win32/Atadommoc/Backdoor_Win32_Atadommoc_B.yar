
rule Backdoor_Win32_Atadommoc_B{
	meta:
		description = "Backdoor:Win32/Atadommoc.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 16 6a 35 68 90 90 1f 00 00 57 ff 75 90 01 01 8b c8 e8 90 00 } //01 00 
		$a_01_1 = {74 14 6a 35 68 91 1f 00 00 56 53 8b c8 e8 } //02 00 
		$a_01_2 = {63 6f 6d 6d 6f 6e 2e 64 61 74 61 } //01 00 
		$a_01_3 = {4a 6f 62 3a 3a 44 65 63 72 79 70 74 } //01 00 
		$a_01_4 = {43 4f 44 45 5f 53 4e 41 50 28 29 } //01 00 
		$a_01_5 = {46 6f 72 6b 49 6e 53 70 6f 6f 6c 28 29 3a } //00 00 
	condition:
		any of ($a_*)
 
}