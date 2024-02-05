
rule Trojan_Win32_RedLineStealer_MOA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 73 6a 64 6e 66 69 73 62 64 66 69 73 64 6f 66 73 64 69 6f 66 } //01 00 
		$a_01_1 = {7a 00 65 00 6c 00 61 00 79 00 75 00 68 00 65 00 66 00 65 00 68 00 65 00 77 00 } //01 00 
		$a_01_2 = {63 61 70 61 73 75 66 69 64 6f 6c 69 64 } //01 00 
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_4 = {53 6c 65 65 70 } //00 00 
	condition:
		any of ($a_*)
 
}