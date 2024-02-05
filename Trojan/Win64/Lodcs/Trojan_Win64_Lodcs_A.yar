
rule Trojan_Win64_Lodcs_A{
	meta:
		description = "Trojan:Win64/Lodcs.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 01 43 32 04 02 41 88 00 49 ff c0 3b f3 72 } //01 00 
		$a_01_1 = {c1 fa 02 8b c2 c1 e8 1f 03 d0 8b c6 ff c6 8d 0c 52 c1 e1 03 2b c1 } //01 00 
		$a_03_2 = {43 6f 6e 76 65 72 74 54 68 72 65 61 64 54 6f 46 69 62 65 72 90 02 0a 56 69 72 74 75 61 6c 41 6c 6c 6f 63 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}