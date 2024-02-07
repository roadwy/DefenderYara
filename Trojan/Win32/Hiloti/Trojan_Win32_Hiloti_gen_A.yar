
rule Trojan_Win32_Hiloti_gen_A{
	meta:
		description = "Trojan:Win32/Hiloti.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {33 c9 3b de 76 08 30 0c 01 41 3b cb 72 f8 50 ff 15 } //02 00 
		$a_03_1 = {75 36 66 83 3d 90 01 04 61 75 2c 66 83 3d 90 01 04 67 75 22 66 83 3d 90 01 04 69 75 18 66 83 3d 90 01 04 63 90 00 } //01 00 
		$a_01_2 = {8b 46 0c 8b 4e 10 03 c1 89 46 0c eb cd 56 8b f1 8d 46 04 } //01 00 
		$a_03_3 = {6a 24 eb 02 6a 1c 90 01 01 ff 15 90 00 } //01 00 
		$a_00_4 = {26 00 63 00 6c 00 76 00 65 00 72 00 3d 00 } //01 00  &clver=
		$a_00_5 = {25 00 73 00 25 00 78 00 2e 00 64 00 6c 00 6c 00 } //00 00  %s%x.dll
	condition:
		any of ($a_*)
 
}