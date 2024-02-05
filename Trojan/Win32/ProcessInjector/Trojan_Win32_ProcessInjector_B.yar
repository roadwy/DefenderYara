
rule Trojan_Win32_ProcessInjector_B{
	meta:
		description = "Trojan:Win32/ProcessInjector.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 66 69 6e 37 5f 69 6e 6a 65 63 74 44 4c 4c 2d 73 68 69 6d 5f 73 74 65 70 31 39 5c 52 65 6c 65 61 73 65 5c 73 74 65 70 31 39 2e 70 64 62 } //01 00 
		$a_01_1 = {5a 77 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00 
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //01 00 
		$a_01_4 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}