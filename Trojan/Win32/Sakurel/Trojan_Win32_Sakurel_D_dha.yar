
rule Trojan_Win32_Sakurel_D_dha{
	meta:
		description = "Trojan:Win32/Sakurel.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 64 5f 6f 66 5f 25 64 5f 66 6f 72 5f 25 73 5f 6f 6e 5f 25 73 00 } //01 00 
		$a_03_1 = {3f 72 65 73 69 64 3d 25 64 90 02 0f 26 70 68 6f 74 6f 69 64 3d 00 90 00 } //01 00 
		$a_01_2 = {8a 0c 10 84 c9 74 0b 80 f9 56 74 06 80 f1 56 88 0c 10 40 3b 45 0c 7c e8 } //01 00 
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 75 6e 64 6c 6c 33 32 20 22 25 73 22 20 50 6c 61 79 65 72 20 25 73 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}