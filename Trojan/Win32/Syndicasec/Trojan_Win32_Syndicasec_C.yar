
rule Trojan_Win32_Syndicasec_C{
	meta:
		description = "Trojan:Win32/Syndicasec.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 47 6c 6f 62 61 6c 2d 3e 6e 4f 53 54 79 70 65 3d 3d 36 34 2d 2d 25 73 5c 63 6d 64 2e 65 78 65 20 25 73 } //01 00 
		$a_01_1 = {5c 43 72 79 70 74 42 61 73 65 2e 64 6c 6c } //01 00 
		$a_01_2 = {67 75 70 64 61 74 65 2e 65 78 65 } //01 00 
		$a_01_3 = {77 75 73 61 2e 65 78 65 } //01 00 
		$a_01_4 = {68 74 74 70 63 6f 6d 2e 6c 6f 67 } //01 00 
		$a_01_5 = {25 73 25 73 2e 64 6c 6c 2e 63 61 62 } //01 00 
		$a_01_6 = {52 65 6c 65 61 73 65 45 76 69 6c 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}