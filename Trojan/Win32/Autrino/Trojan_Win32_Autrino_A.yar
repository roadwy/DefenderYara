
rule Trojan_Win32_Autrino_A{
	meta:
		description = "Trojan:Win32/Autrino.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 5f 75 5f 54 6a 5f 4e 6f 31 32 33 33 32 31 45 78 65 } //01 00 
		$a_01_1 = {63 73 62 6f 79 62 69 6e 64 2e 61 75 } //01 00 
		$a_01_2 = {54 68 75 6e 64 65 72 50 6c 61 74 66 6f 72 6d 2e 65 78 65 } //01 00 
		$a_01_3 = {73 74 6f 72 6d 6c 69 76 2e 65 78 65 } //01 00 
		$a_01_4 = {63 73 62 6f 79 44 56 44 2e 64 6c 6c } //00 00 
		$a_00_5 = {5d 04 00 } //00 c7 
	condition:
		any of ($a_*)
 
}