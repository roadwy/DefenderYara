
rule Trojan_Win32_Ilomo_gen_A{
	meta:
		description = "Trojan:Win32/Ilomo.gen!A,SIGNATURE_TYPE_PEHSTR,02 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 0f 04 41 88 06 46 c1 ea 04 e2 f2 c6 06 00 5e 8b 7d 04 83 c7 15 33 c0 56 57 50 6a 04 50 6a ff b8 44 33 22 11 ff d0 } //01 00 
		$a_01_1 = {8b 55 b8 8b 42 20 ff d0 85 c0 74 44 6a 05 8b 4d b8 8b 11 52 8b 45 b8 8b 48 24 ff d1 6a 00 6a 00 8b 55 b8 8b 02 50 8d 4d 98 } //00 00 
	condition:
		any of ($a_*)
 
}