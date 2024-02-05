
rule Trojan_Win32_Alureon_gen_R{
	meta:
		description = "Trojan:Win32/Alureon.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 44 44 41 4d 68 32 4c 44 54 } //01 00 
		$a_01_1 = {5c 44 65 76 69 63 65 5c 4e 50 52 4f 54 5f 25 73 00 } //01 00 
		$a_01_2 = {2d 63 53 82 63 f7 d8 1b c0 } //01 00 
		$a_01_3 = {38 35 2e 32 35 35 2e 31 31 32 2e 33 36 3b 38 35 } //01 00 
		$a_01_4 = {8a d1 02 d0 30 14 31 83 c1 01 3b cf 72 f2 } //00 00 
	condition:
		any of ($a_*)
 
}