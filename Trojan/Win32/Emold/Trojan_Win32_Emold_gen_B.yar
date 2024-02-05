
rule Trojan_Win32_Emold_gen_B{
	meta:
		description = "Trojan:Win32/Emold.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 00 31 6f 61 64 4c 69 62 72 61 72 79 41 00 6e 74 64 6c 6c 2e 64 6c 6c } //02 00 
		$a_03_1 = {e9 0b 01 00 00 45 6e 74 65 72 20 74 65 78 74 20 68 65 72 65 90 01 04 4e 4f 54 45 50 41 44 2e 45 58 45 00 53 65 74 20 54 65 78 74 90 00 } //04 00 
		$a_03_2 = {28 07 30 07 47 e2 f9 eb 90 09 0a 00 bf 90 01 04 b9 90 01 02 00 00 90 00 } //02 00 
		$a_01_3 = {ab a1 ab a6 95 8d 9e 9b 85 8c 8c 75 70 86 9b 6f 70 86 8c 6f 6e ab 75 86 9e ab 75 8c 88 71 7b 75 8b } //00 00 
	condition:
		any of ($a_*)
 
}