
rule Trojan_Win32_Alureon_DM{
	meta:
		description = "Trojan:Win32/Alureon.DM,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {61 66 66 69 64 3d 25 73 26 73 75 62 69 64 3d 25 73 00 00 00 2f 63 72 2f 63 66 2e 70 68 70 00 } //02 00 
		$a_01_1 = {68 38 73 72 74 64 61 74 61 2e 64 6c 6c 00 } //01 00 
		$a_01_2 = {5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 } //01 00 
		$a_01_3 = {54 68 72 65 61 64 53 70 61 6d 28 29 31 31 31 31 31 31 31 31 31 31 } //02 00 
		$a_01_4 = {8d 49 00 8a d0 80 c2 54 30 14 30 83 c0 01 3b c7 72 } //00 00 
	condition:
		any of ($a_*)
 
}