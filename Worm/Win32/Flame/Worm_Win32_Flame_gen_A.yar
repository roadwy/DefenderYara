
rule Worm_Win32_Flame_gen_A{
	meta:
		description = "Worm:Win32/Flame.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 e9 18 8b d8 c1 eb 10 32 cb 8b d8 c1 eb 08 32 cb 32 c8 28 0e 46 4a 75 } //02 00 
		$a_01_1 = {33 c0 c3 66 81 3e 4d 5a 75 f6 8b 46 3c 03 c6 } //02 00 
		$a_01_2 = {81 f9 db df ac a2 74 18 81 f9 fc fe ba b0 } //01 00 
		$a_01_3 = {55 00 50 00 44 00 54 00 5f 00 53 00 59 00 4e 00 43 00 5f 00 4d 00 54 00 58 00 5f 00 54 00 4d 00 45 00 } //01 00 
		$a_01_4 = {54 00 48 00 5f 00 50 00 4f 00 4f 00 4c 00 5f 00 53 00 48 00 44 00 5f 00 } //02 00 
		$a_01_5 = {8b 4e 1c ff 75 08 41 51 50 89 46 0c e8 } //00 00 
	condition:
		any of ($a_*)
 
}