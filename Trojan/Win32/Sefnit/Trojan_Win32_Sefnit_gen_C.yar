
rule Trojan_Win32_Sefnit_gen_C{
	meta:
		description = "Trojan:Win32/Sefnit.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6f 75 74 70 75 74 5c 4d 69 6e 53 69 7a 65 52 65 6c 5c 62 61 63 6b 64 6f 6f 72 2e 70 64 62 00 } //01 00 
		$a_81_1 = {2e 63 6f 6d 2f 67 65 74 74 61 73 6b 73 2e 70 68 70 00 } //01 00 
		$a_01_2 = {2f 00 6d 00 6f 00 64 00 2e 00 70 00 68 00 70 00 } //01 00  /mod.php
		$a_01_3 = {47 6c 6f 62 61 6c 5c 7b 33 39 44 35 46 43 35 34 2d 44 44 33 36 2d 34 31 61 66 2d 39 33 45 36 2d 44 45 45 33 30 30 32 44 46 42 41 25 64 7d 00 } //00 00 
	condition:
		any of ($a_*)
 
}