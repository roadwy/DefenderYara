
rule Trojan_Win32_BazarLdr_C_ibt{
	meta:
		description = "Trojan:Win32/BazarLdr.C!ibt,SIGNATURE_TYPE_PEHSTR,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 22 00 26 00 20 00 7b 00 41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 } //02 00 
		$a_01_1 = {53 00 65 00 74 00 2d 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 50 00 6f 00 6c 00 69 00 63 00 79 00 20 00 2d 00 53 00 63 00 6f 00 70 00 65 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 42 00 79 00 70 00 61 00 73 00 73 00 } //01 00 
		$a_01_2 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 4f 00 6e 00 63 00 65 00 } //01 00 
		$a_01_3 = {73 65 6c 66 44 65 6c 65 74 65 } //01 00 
		$a_01_4 = {61 75 74 6f 72 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}