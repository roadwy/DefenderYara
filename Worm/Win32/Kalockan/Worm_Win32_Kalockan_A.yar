
rule Worm_Win32_Kalockan_A{
	meta:
		description = "Worm:Win32/Kalockan.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {26 70 72 6f 73 3d 90 02 08 2f 67 61 74 65 5f 75 72 6c 7a 6f 6e 65 2f 90 00 } //01 00 
		$a_03_1 = {25 42 4f 54 49 44 25 90 02 08 25 42 4f 54 4e 45 54 25 90 00 } //01 00 
		$a_03_2 = {26 69 70 63 6e 66 3d 90 02 08 26 73 63 6b 70 6f 72 74 3d 90 00 } //01 00 
		$a_03_3 = {25 4c 4f 43 4b 44 4f 4d 41 49 4e 25 90 02 08 25 4c 4f 43 4b 4d 45 53 53 41 47 45 25 90 00 } //01 00 
		$a_03_4 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 02 08 7c 45 6e 64 90 00 } //00 00 
		$a_00_5 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}