
rule Trojan_Win32_Nebuler_gen_G{
	meta:
		description = "Trojan:Win32/Nebuler.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 1d 8b 45 08 03 45 f8 0f be 40 01 0f b6 0d 90 01 04 33 c1 8b 4d f4 03 4d f8 88 01 eb d4 90 00 } //01 00 
		$a_03_1 = {0f be 17 33 c9 85 d2 76 1c 8d a4 24 00 00 00 00 8a 44 0f 01 34 90 01 01 88 04 31 41 3b ca 72 f2 c6 04 32 00 90 00 } //01 00 
		$a_01_2 = {8a 14 07 32 54 0b 01 41 88 10 40 3b ce 72 f1 } //01 00 
		$a_01_3 = {8a 1c 17 32 5c 29 01 41 88 1a 42 3b ce 72 f1 } //01 00 
		$a_01_4 = {8a d0 80 ea 15 30 54 04 0c 40 3b c3 7c f2 } //01 00 
		$a_01_5 = {5b 62 72 61 6e 64 5d 00 5b 76 65 72 73 69 6f 6e 5d 00 00 00 5b 75 69 64 5d } //00 00 
	condition:
		any of ($a_*)
 
}