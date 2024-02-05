
rule Backdoor_Win32_Paras_C{
	meta:
		description = "Backdoor:Win32/Paras.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 48 6f 77 41 72 4d 65 2e 72 65 67 } //01 00 
		$a_01_1 = {5c 4d 79 53 6f 6d 65 49 6e 66 6f 2e 69 6e 69 } //01 00 
		$a_01_2 = {33 36 30 69 6e 73 74 2e 65 78 65 00 33 36 30 74 72 61 79 2e 65 78 65 } //01 00 
		$a_01_3 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //00 00 
	condition:
		any of ($a_*)
 
}