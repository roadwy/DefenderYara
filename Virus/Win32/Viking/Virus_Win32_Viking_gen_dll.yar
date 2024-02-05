
rule Virus_Win32_Viking_gen_dll{
	meta:
		description = "Virus:Win32/Viking.gen!dll,SIGNATURE_TYPE_PEHSTR,0d 00 0c 00 0a 00 00 03 00 "
		
	strings :
		$a_01_0 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 } //03 00 
		$a_01_1 = {d5 d2 cc c4 ef f7 ee ec ef e1 e4 d4 ef c6 e9 ec } //03 00 
		$a_01_2 = {dc ed e9 e3 f2 ef f3 ef e6 f4 dc } //02 00 
		$a_01_3 = {e8 f4 f4 f0 ba af af } //01 00 
		$a_01_4 = {63 3a 5c 31 2e 74 78 74 } //01 00 
		$a_01_5 = {64 33 3a 00 ff ff ff ff 03 } //01 00 
		$a_01_6 = {64 34 3a 00 ff ff ff ff 03 } //01 00 
		$a_01_7 = {41 43 44 53 65 65 34 2e 65 78 65 } //01 00 
		$a_01_8 = {55 65 64 69 74 33 32 2e 65 78 65 } //01 00 
		$a_01_9 = {20 2f 68 65 68 65 } //00 00 
	condition:
		any of ($a_*)
 
}