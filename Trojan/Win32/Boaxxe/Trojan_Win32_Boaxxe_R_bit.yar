
rule Trojan_Win32_Boaxxe_R_bit{
	meta:
		description = "Trojan:Win32/Boaxxe.R!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 69 00 00 00 8b 0d 90 01 04 66 89 01 ba 6e 00 00 00 a1 90 01 04 66 89 50 02 b9 66 00 00 00 8b 15 90 01 04 66 89 4a 0a b8 61 00 00 00 8b 0d 90 01 04 66 89 41 0c ba 63 00 00 00 a1 90 01 04 66 89 50 0e b9 7b 00 00 00 8b 15 90 01 04 66 89 4a 14 b8 7d 00 00 00 8b 0d 90 01 04 66 89 41 5e 90 00 } //01 00 
		$a_03_1 = {83 c4 04 a3 90 01 04 c7 85 90 01 08 8b 8d 90 01 04 c6 01 56 8b 95 90 01 04 52 68 90 01 04 ff 15 90 01 04 50 ff 15 b0 60 40 00 90 00 } //01 00 
		$a_03_2 = {72 02 eb 2a 8b 45 90 01 01 89 85 90 01 04 8b 4d 90 01 01 03 8d 90 01 04 8b 55 90 01 01 03 95 90 01 04 8a 02 88 01 8b 4d 90 01 01 83 c1 01 89 4d 90 01 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}