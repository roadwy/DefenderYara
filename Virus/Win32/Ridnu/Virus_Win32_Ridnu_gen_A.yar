
rule Virus_Win32_Ridnu_gen_A{
	meta:
		description = "Virus:Win32/Ridnu.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 72 5f 43 6f 6f 6c 46 61 63 65 2e 73 63 72 } //01 00 
		$a_00_1 = {2e 70 69 66 20 2e 62 61 74 20 2e 63 6f 6d 20 2e 73 63 72 20 2e 65 78 65 } //01 00 
		$a_01_2 = {8a 10 8a ca 3a 16 75 1c 3a cb 74 14 8a 50 01 8a ca 3a 56 01 75 0e 83 c0 02 83 c6 02 3a cb 75 e0 } //00 00 
	condition:
		any of ($a_*)
 
}