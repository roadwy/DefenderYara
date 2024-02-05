
rule Trojan_Win32_Zopharp_A{
	meta:
		description = "Trojan:Win32/Zopharp.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 68 61 72 6d 69 6e 67 28 24 64 61 74 61 6f 6e 65 29 3b } //01 00 
		$a_01_1 = {66 6f 70 65 6e 28 22 43 3a 5c 5c 77 69 6e 64 6f 77 73 5c 5c 73 79 73 74 65 6d 33 32 5c 5c 64 72 69 76 65 72 73 5c 5c 65 74 63 5c 5c 68 6f 73 74 73 22 2c 22 77 2b 22 29 3b } //01 00 
		$a_01_2 = {24 73 65 72 76 20 3d 20 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 28 22 24 75 72 6c 64 6f 6e 77 22 29 3b } //00 00 
	condition:
		any of ($a_*)
 
}