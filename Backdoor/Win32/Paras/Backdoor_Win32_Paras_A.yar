
rule Backdoor_Win32_Paras_A{
	meta:
		description = "Backdoor:Win32/Paras.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 4b 14 8b 53 20 51 52 e8 } //01 00 
		$a_00_1 = {00 53 65 72 76 65 72 4c 6f 61 64 2e 64 6c 6c } //01 00 
		$a_00_2 = {5c 73 79 73 6c 6f 67 2e 64 61 74 00 } //01 00 
		$a_00_3 = {00 72 65 6d 6f 76 65 73 65 72 76 69 63 65 00 } //01 00 
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 61 74 61 41 63 63 65 73 73 5c 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}