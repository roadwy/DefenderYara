
rule Trojan_Win32_Sirefef_gen_C{
	meta:
		description = "Trojan:Win32/Sirefef.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {3a 5c 56 43 35 5c 72 65 6c 65 61 73 65 5c 6b 69 6e 6a 65 63 74 2e 64 6c 6c 2e 70 64 62 } //01 00 
		$a_00_1 = {76 65 72 73 69 6f 6e 3d 30 26 65 72 72 3d 25 73 26 6c 3d 25 64 26 63 3d 25 64 20 48 54 54 50 2f 31 2e 31 } //01 00 
		$a_02_2 = {77 77 77 2e 67 6f 6f 67 6c 65 2e 90 02 06 25 73 25 73 90 02 04 26 63 78 3d 90 02 04 26 63 6c 69 65 6e 74 3d 90 00 } //01 00 
		$a_00_3 = {52 65 66 65 72 65 72 3a 20 25 53 25 53 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Sirefef_gen_C_2{
	meta:
		description = "Trojan:Win32/Sirefef.gen!C,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {3a 5c 56 43 35 5c 72 65 6c 65 61 73 65 5c 6b 69 6e 6a 65 63 74 2e 64 6c 6c 2e 70 64 62 } //01 00 
		$a_00_1 = {76 65 72 73 69 6f 6e 3d 30 26 65 72 72 3d 25 73 26 6c 3d 25 64 26 63 3d 25 64 20 48 54 54 50 2f 31 2e 31 } //01 00 
		$a_02_2 = {77 77 77 2e 67 6f 6f 67 6c 65 2e 90 02 06 25 73 25 73 90 02 04 26 63 78 3d 90 02 04 26 63 6c 69 65 6e 74 3d 90 00 } //01 00 
		$a_00_3 = {52 65 66 65 72 65 72 3a 20 25 53 25 53 } //00 00 
	condition:
		any of ($a_*)
 
}