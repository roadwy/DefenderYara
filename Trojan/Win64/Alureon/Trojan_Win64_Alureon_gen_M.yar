
rule Trojan_Win64_Alureon_gen_M{
	meta:
		description = "Trojan:Win64/Alureon.gen!M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 43 04 66 ff 43 06 41 bd 64 86 00 00 66 41 3b c5 75 03 01 7b 50 } //01 00 
		$a_01_1 = {74 22 44 8b 43 54 4c 8b c8 33 d2 33 c9 4c 03 c0 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 53 18 48 8b cf ff 13 } //01 00 
		$a_01_2 = {42 0f b6 04 11 41 32 44 1b ff 49 ff c9 88 43 ff 75 a3 48 83 c4 20 5b c3 } //01 00 
		$a_01_3 = {73 64 72 6f 70 70 65 72 36 34 2e 65 78 65 00 44 6f 77 6e 6c 6f 61 64 52 75 6e 45 78 65 49 64 } //00 00 
	condition:
		any of ($a_*)
 
}