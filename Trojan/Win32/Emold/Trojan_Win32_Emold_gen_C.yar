
rule Trojan_Win32_Emold_gen_C{
	meta:
		description = "Trojan:Win32/Emold.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 81 3f 4d 5a 75 90 01 01 8b 47 3c 89 fe 01 c7 66 81 3f 50 45 75 90 01 01 89 f0 90 00 } //01 00 
		$a_01_1 = {00 31 6f 61 64 4c 69 62 72 61 72 79 41 00 } //02 00 
		$a_03_2 = {28 07 30 07 47 e2 f9 eb 90 09 0a 00 bf 90 01 04 b9 90 01 02 00 00 90 00 } //02 00 
		$a_03_3 = {6a 00 6a 00 ff 15 90 01 02 40 00 31 c0 5f 5e 5b c9 c2 10 00 ff 15 90 01 02 40 00 89 c3 b8 90 01 02 00 00 28 d8 b9 90 01 02 40 00 29 d9 ff e1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}