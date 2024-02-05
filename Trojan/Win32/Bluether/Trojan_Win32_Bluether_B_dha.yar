
rule Trojan_Win32_Bluether_B_dha{
	meta:
		description = "Trojan:Win32/Bluether.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {30 a8 b3 10 6b 4e 09 a1 dd 8e cc 51 49 5e 32 00 26 12 63 ed 03 47 56 a7 } //03 00 
		$a_01_1 = {25 30 34 58 2f 25 63 25 64 2e 61 73 70 } //02 00 
		$a_01_2 = {72 75 6e 20 6f 6b 21 } //02 00 
		$a_01_3 = {69 73 20 6e 6f 74 20 65 78 69 73 74 20 70 61 74 68 21 } //02 00 
		$a_01_4 = {74 77 2e 63 68 61 74 6e 6f 6f 6b 2e 63 6f 6d 3a 38 30 2c 34 34 33 3b 74 77 6e 69 63 2e 63 72 61 62 64 61 6e 63 65 2e 63 6f 6d 3a 38 30 2c 34 34 33 3b 61 73 75 73 2e 73 74 72 61 6e 67 6c 65 64 2e 6e 65 74 3a 38 30 2c 34 34 33 3b } //00 00 
		$a_00_5 = {5d 04 00 00 18 } //32 03 
	condition:
		any of ($a_*)
 
}