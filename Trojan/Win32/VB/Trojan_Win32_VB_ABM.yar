
rule Trojan_Win32_VB_ABM{
	meta:
		description = "Trojan:Win32/VB.ABM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 6e 00 68 00 61 00 63 00 6b 00 2e 00 63 00 6e 00 2f 00 6f 00 6b 00 2f 00 32 00 63 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_1 = {63 00 6e 00 68 00 61 00 63 00 6b 00 2e 00 63 00 6e 00 2f 00 6f 00 6b 00 2f 00 63 00 73 00 2f 00 73 00 66 00 63 00 70 00 63 00 31 00 2f 00 6b 00 31 00 2e 00 74 00 78 00 74 00 } //01 00 
		$a_01_2 = {75 00 77 00 65 00 72 00 75 00 75 00 79 00 71 00 2e 00 63 00 6e 00 2f 00 64 00 6d 00 31 00 2e 00 68 00 74 00 6d 00 3f 00 } //01 00 
		$a_01_3 = {76 00 69 00 70 00 32 00 2e 00 35 00 31 00 2e 00 6c 00 61 00 2f 00 67 00 6f 00 2e 00 61 00 73 00 70 00 3f 00 77 00 65 00 3d 00 41 00 2d 00 46 00 72 00 65 00 65 00 2d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2d 00 66 00 6f 00 72 00 2d 00 57 00 65 00 62 00 6d 00 61 00 73 00 74 00 65 00 72 00 73 00 26 00 73 00 76 00 69 00 64 00 3d 00 37 00 26 00 69 00 64 00 3d 00 31 00 37 00 38 00 39 00 31 00 32 00 37 00 } //01 00 
		$a_01_4 = {3c 00 61 00 20 00 68 00 72 00 65 00 66 00 3d 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 71 00 71 00 2e 00 63 00 6f 00 6d 00 2f 00 3e 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 3c 00 2f 00 61 00 3e 00 } //00 00 
	condition:
		any of ($a_*)
 
}