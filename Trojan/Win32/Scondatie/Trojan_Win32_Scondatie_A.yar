
rule Trojan_Win32_Scondatie_A{
	meta:
		description = "Trojan:Win32/Scondatie.A,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 06 00 00 64 00 "
		
	strings :
		$a_01_0 = {44 4d 54 4f 4f 4c } //0a 00 
		$a_01_1 = {46 69 6c 65 73 5c 61 5c 73 79 6e 65 63 2e 74 78 74 } //0a 00 
		$a_01_2 = {4d 65 65 74 69 6e 67 73 5c 61 5c 73 79 6e 65 63 2e 65 78 65 } //01 00 
		$a_03_3 = {78 69 61 6e 67 78 69 2e 90 11 03 00 00 90 00 } //01 00 
		$a_01_4 = {6a 70 67 74 75 2e 64 61 74 } //01 00 
		$a_01_5 = {68 61 6f 74 75 2e 64 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}