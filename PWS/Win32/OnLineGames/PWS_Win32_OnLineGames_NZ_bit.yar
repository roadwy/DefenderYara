
rule PWS_Win32_OnLineGames_NZ_bit{
	meta:
		description = "PWS:Win32/OnLineGames.NZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 04 00 "
		
	strings :
		$a_03_0 = {54 72 6f 6a 61 6e 44 4c 4c 2e 64 6c 6c 90 02 10 48 6f 6f 6b 90 00 } //01 00 
		$a_01_1 = {53 65 74 48 6f 6f 6b 00 55 6e 48 6f 6f 6b 00 } //01 00 
		$a_01_2 = {3f 61 74 3d 6c 6f 63 6b 26 73 31 33 3d } //01 00 
		$a_01_3 = {26 74 62 42 61 6e 6b 50 77 64 3d } //01 00 
		$a_01_4 = {22 6c 62 42 61 6e 6b 4d 6f 6e 65 79 22 3e } //01 00 
		$a_01_5 = {22 6c 62 42 61 67 4d 6f 6e 65 79 22 3e } //00 00 
	condition:
		any of ($a_*)
 
}
rule PWS_Win32_OnLineGames_NZ_bit_2{
	meta:
		description = "PWS:Win32/OnLineGames.NZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6e 73 5f 68 65 6c 70 65 72 2e 64 6c 6c } //01 00 
		$a_01_1 = {63 66 5f 72 65 70 61 69 72 2e 64 6c 6c } //01 00 
		$a_01_2 = {64 6e 66 5f 68 65 6c 70 65 72 2e 64 6c 6c } //01 00 
		$a_01_3 = {6c 6f 6c 5f 74 6f 6f 6c 73 2e 64 6c 6c } //01 00 
		$a_01_4 = {67 61 6d 65 5f 6d 67 72 2e 64 6c 6c 2e 64 6c 6c } //04 00 
		$a_01_5 = {54 72 6f 6a 61 6e 44 4c 4c 2e 64 6c 6c 00 48 61 6e 64 6c 65 48 6f 6f 6b 52 65 63 76 44 61 74 61 5f 46 72 6f 6d 4c 73 70 } //01 00 
		$a_01_6 = {53 65 74 48 6f 6f 6b 00 55 6e 48 6f 6f 6b 00 } //00 00 
	condition:
		any of ($a_*)
 
}