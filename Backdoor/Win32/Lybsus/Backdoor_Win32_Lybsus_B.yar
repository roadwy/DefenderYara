
rule Backdoor_Win32_Lybsus_B{
	meta:
		description = "Backdoor:Win32/Lybsus.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 6d 72 43 61 6d 53 74 61 72 74 } //01 00 
		$a_00_1 = {4d 00 53 00 4e 00 43 00 4f 00 4e 00 54 00 41 00 43 00 54 00 } //01 00 
		$a_00_2 = {53 00 48 00 45 00 4c 00 4c 00 48 00 4f 00 4f 00 4b 00 } //01 00 
		$a_00_3 = {43 00 6f 00 6e 00 65 00 63 00 74 00 61 00 64 00 6f 00 } //01 00 
		$a_00_4 = {52 00 45 00 43 00 49 00 42 00 49 00 44 00 4f 00 } //00 00 
	condition:
		any of ($a_*)
 
}