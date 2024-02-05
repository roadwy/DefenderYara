
rule Worm_Win32_Phelshap_A{
	meta:
		description = "Worm:Win32/Phelshap.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 63 65 73 73 20 49 44 20 6f 66 20 27 73 68 61 6b 68 70 65 6c 27 20 69 73 20 25 64 } //01 00 
		$a_01_1 = {4e 6f 20 55 53 42 20 44 72 69 76 65 } //01 00 
		$a_01_2 = {25 73 5c 54 69 67 68 74 56 4e 43 5c 76 6e 63 2e 64 61 74 } //01 00 
		$a_01_3 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 3d 74 69 67 68 56 6e 63 53 65 74 75 70 5c 76 6e 63 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}