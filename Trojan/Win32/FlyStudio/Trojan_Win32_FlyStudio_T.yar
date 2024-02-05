
rule Trojan_Win32_FlyStudio_T{
	meta:
		description = "Trojan:Win32/FlyStudio.T,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 69 67 66 78 74 72 61 79 } //03 00 
		$a_01_1 = {5c 7a 68 75 6f 6d 69 61 6e 2e 6a 70 67 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //02 00 
		$a_01_3 = {45 52 61 77 53 6f 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FlyStudio_T_2{
	meta:
		description = "Trojan:Win32/FlyStudio.T,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 02 00 00 80 6a 00 68 00 00 00 00 68 04 00 00 80 6a 00 68 90 01 03 00 68 03 00 00 00 bb 90 01 03 00 e8 90 00 } //01 00 
		$a_03_1 = {68 04 00 00 80 6a 00 68 90 01 03 00 68 01 00 00 00 b8 01 00 00 00 bb 90 01 03 00 e8 90 00 } //01 00 
		$a_02_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 31 31 31 6d 2e 69 6e 66 6f 2f 76 69 70 2f 76 69 70 90 01 01 2e 6a 70 67 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}