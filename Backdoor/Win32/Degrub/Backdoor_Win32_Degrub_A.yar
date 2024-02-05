
rule Backdoor_Win32_Degrub_A{
	meta:
		description = "Backdoor:Win32/Degrub.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 63 72 65 65 6e 20 54 68 69 65 66 20 53 65 72 76 65 72 3a } //01 00 
		$a_01_1 = {53 65 6e 64 69 6e 67 20 73 63 72 65 65 6e 20 73 68 6f 74 3a } //01 00 
		$a_01_2 = {43 3a 5c 49 6e 74 65 6c 5c 6d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c } //01 00 
		$a_01_3 = {54 61 6b 65 53 68 6f 74 } //01 00 
		$a_01_4 = {6b 65 79 6c 6f 67 67 65 72 } //00 00 
		$a_00_5 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}