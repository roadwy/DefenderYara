
rule Trojan_Win32_Kilim_P{
	meta:
		description = "Trojan:Win32/Kilim.P,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 22 68 74 74 70 3a 2f 2f 77 68 6f 73 2e 61 6d 75 6e 67 2e 75 73 2f 70 69 6e 67 6a 73 2f 3f 6b 3d 90 02 0f 2c 20 22 70 69 6e 67 6a 73 2e 6a 73 22 90 00 } //01 00 
		$a_03_1 = {47 65 74 44 6f 77 6e 6c 6f 61 64 28 90 02 08 5f 4c 69 6e 6b 2c 20 22 90 03 02 03 62 67 63 72 78 2e 74 78 74 22 2c 20 33 2c 20 31 29 90 00 } //01 00 
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 63 68 72 6f 6d 65 2e 65 78 65 20 2f 46 } //00 00 
		$a_00_3 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}