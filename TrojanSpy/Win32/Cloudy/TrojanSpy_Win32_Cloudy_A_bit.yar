
rule TrojanSpy_Win32_Cloudy_A_bit{
	meta:
		description = "TrojanSpy:Win32/Cloudy.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6c 6f 75 64 79 73 65 72 76 73 2e 63 6f 6d } //01 00 
		$a_01_1 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 43 6c 6f 75 64 79 } //01 00 
		$a_01_2 = {47 6c 6f 62 61 6c 5c 7b 4a 51 5a 58 43 2d 35 32 39 36 34 2d 47 54 48 4a 2d 51 4b 49 55 2d 35 36 50 4f 55 59 54 7d } //01 00 
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_4 = {5c 52 65 6c 65 61 73 65 5c 43 6c 6f 75 64 79 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}