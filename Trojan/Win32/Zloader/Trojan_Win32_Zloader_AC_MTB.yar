
rule Trojan_Win32_Zloader_AC_MTB{
	meta:
		description = "Trojan:Win32/Zloader.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {36 43 c0 63 ff 48 d0 41 d0 0c 8b 80 e9 c0 ff 09 21 24 74 28 ff be 90 02 04 58 d2 48 8b 82 f8 f1 8b 00 70 90 00 } //01 00 
		$a_03_1 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 90 01 04 83 f9 90 01 01 0f 82 90 01 04 81 f9 90 01 04 73 13 0f ba 25 90 01 04 01 0f 82 90 01 04 e9 90 01 04 0f ba 25 90 01 04 01 73 09 f3 a4 90 00 } //01 00 
		$a_00_2 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 } //01 00 
		$a_81_3 = {3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00 
		$a_81_4 = {5c 51 75 69 65 74 5c 46 75 6e 5c 49 6e 73 65 63 74 5c 43 61 72 72 79 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}