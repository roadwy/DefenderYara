
rule Trojan_Win32_Radonskra_D{
	meta:
		description = "Trojan:Win32/Radonskra.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {2f 63 72 65 61 74 65 20 2f 74 6e 90 02 10 2f 74 72 20 22 44 57 56 41 4c 55 45 22 20 2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 66 90 00 } //01 00 
		$a_02_1 = {68 74 74 70 3a 2f 2f 90 02 10 2e 72 75 2f 90 02 10 2e 70 68 70 3f 73 6e 69 64 3d 90 00 } //01 00 
		$a_00_2 = {64 2e 6c 6f 63 61 74 69 6f 6e 2e 70 72 6f 74 6f 63 6f 6c 3d 3d 27 68 74 74 70 73 3a 27 29 65 78 69 74 3b 6f 75 72 64 6f 6d 3d 27 48 54 54 50 27 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}