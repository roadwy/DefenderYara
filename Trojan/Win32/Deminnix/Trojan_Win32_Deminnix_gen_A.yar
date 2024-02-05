
rule Trojan_Win32_Deminnix_gen_A{
	meta:
		description = "Trojan:Win32/Deminnix.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {b1 6f b2 73 80 3c 37 3c 75 2e 38 4c 37 01 75 28 80 7c 37 02 70 75 21 80 7c 37 03 74 75 1a 80 7c 37 04 69 75 13 38 4c 37 05 75 0d 80 7c 37 06 6e 75 06 38 54 37 07 74 09 83 c7 01 3b f8 72 c5 eb 49 68 ff 07 00 00 } //02 00 
		$a_01_1 = {76 75 80 3c 33 3c 75 31 80 7c 33 01 6f 75 2a 80 7c 33 02 70 75 23 80 7c 33 03 74 75 1c 80 7c 33 04 69 75 15 80 7c 33 05 6f 75 0e 80 7c 33 06 6e 75 07 80 7c 33 07 73 74 07 43 3b d8 72 c4 eb 37 68 ff 07 00 00 } //02 00 
		$a_03_2 = {0f be 42 05 83 f8 6f 75 6e 8b 4d 90 01 01 03 4d 90 01 01 0f be 51 06 83 fa 6e 75 5f 8b 45 90 01 01 03 45 90 01 01 0f be 48 07 83 f9 73 75 50 c6 85 90 01 04 00 68 ff 07 00 00 90 00 } //01 00 
		$a_01_3 = {53 00 65 00 61 00 72 00 63 00 68 00 49 00 6e 00 64 00 65 00 78 00 65 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}