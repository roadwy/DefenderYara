
rule Trojan_Win32_Huradikal_A{
	meta:
		description = "Trojan:Win32/Huradikal.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 66 75 5f 65 64 6f 74 67 e1 } //01 00 
		$a_03_1 = {3a 25 64 00 3a 2f 2f 90 01 1d 2f 50 54 2f 90 00 } //01 00 
		$a_01_2 = {2f 55 53 2f 00 00 00 00 2f 50 4f 2f 00 00 00 00 2f 57 53 2f 00 00 00 00 2f 50 43 2f 00 00 00 00 26 25 73 3d 00 00 00 00 3f 25 73 3d } //01 00 
		$a_01_3 = {2f 73 79 73 74 65 6d 2f 63 70 61 73 73 2e 62 69 6e } //01 00  /system/cpass.bin
		$a_03_4 = {23 63 68 72 6f 6d 65 70 61 73 73 90 02 04 23 68 75 67 62 6f 74 6d 6f 64 90 02 04 23 67 61 6d 65 73 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 70 
	condition:
		any of ($a_*)
 
}