
rule Trojan_Win32_Balisdat_gen_D{
	meta:
		description = "Trojan:Win32/Balisdat.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 6d 72 55 41 43 54 69 6d 65 72 } //01 00  TmrUACTimer
		$a_03_1 = {8d 45 d4 e8 90 01 04 ff 75 d4 68 90 01 04 8d 55 d0 b8 90 01 04 e8 90 01 04 ff 75 d0 b8 90 01 04 ba 04 00 00 00 e8 90 01 04 68 90 01 04 68 90 01 04 68 90 01 04 8d 45 cc e8 90 01 04 ff 75 cc 90 00 } //01 00 
		$a_03_2 = {50 6a 00 6a 00 e8 90 01 04 a1 90 01 04 c7 00 01 00 00 00 a1 90 01 04 8b 00 8b 80 90 01 01 03 00 00 b2 01 e8 90 01 04 eb 1f a1 90 01 04 c7 00 02 00 00 00 a1 90 01 04 8b 00 8b 80 90 1b 03 03 00 00 b2 01 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}