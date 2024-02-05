
rule Trojan_Win32_Dishigy_E{
	meta:
		description = "Trojan:Win32/Dishigy.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 6f 6f 67 6c 65 62 6f 74 } //01 00 
		$a_00_1 = {40 73 6f 6d 65 77 68 65 72 65 } //01 00 
		$a_02_2 = {26 73 79 6e 61 66 70 63 00 90 02 30 24 73 79 6e 61 69 70 00 90 00 } //01 00 
		$a_01_3 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1 } //01 00 
		$a_00_4 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}