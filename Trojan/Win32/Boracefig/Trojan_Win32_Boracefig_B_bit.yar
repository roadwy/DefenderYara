
rule Trojan_Win32_Boracefig_B_bit{
	meta:
		description = "Trojan:Win32/Boracefig.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 7c 24 18 76 0f 85 90 01 04 80 7c 24 19 64 0f 85 90 00 } //01 00 
		$a_01_1 = {32 c2 66 0f b6 d2 66 c1 e7 08 66 0b fa 66 33 7c 24 14 88 44 24 0d } //02 00 
		$a_03_2 = {8a 4c 14 30 8a c2 f6 ea 04 03 84 c9 74 0a 3a c8 74 06 32 c8 88 4c 14 30 42 81 fa 90 01 04 72 90 00 } //01 00 
		$a_01_3 = {44 45 4c 45 54 45 2d 54 43 42 } //01 00 
		$a_01_4 = {44 69 72 20 25 64 6b 20 28 25 64 29 } //01 00 
		$a_01_5 = {2f 2f 25 73 2f 25 35 2e 35 64 2e 68 74 6d 6c } //00 00 
	condition:
		any of ($a_*)
 
}