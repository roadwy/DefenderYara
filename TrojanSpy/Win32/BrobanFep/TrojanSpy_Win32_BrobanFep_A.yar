
rule TrojanSpy_Win32_BrobanFep_A{
	meta:
		description = "TrojanSpy:Win32/BrobanFep.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 5c 64 7b 36 7d 20 2b 5c 5c 64 20 2b 5c 5c 64 7b 31 34 7d 2f 67 } //01 00 
		$a_01_1 = {7c 62 6f 6c 65 74 6f 7c } //01 00 
		$a_01_2 = {7c 49 54 41 55 7c } //01 00 
		$a_01_3 = {7c 42 52 41 44 45 53 43 4f 7c } //01 00 
		$a_01_4 = {7c 53 41 4e 54 41 4e 44 45 52 7c } //01 00 
		$a_01_5 = {7c 43 41 49 58 41 7c } //01 00 
		$a_01_6 = {7c 67 65 74 42 69 6c 6c 65 74 4e 75 6d 62 65 72 7c } //01 00 
		$a_01_7 = {7c 43 61 6d 70 6f 63 6f 64 69 67 6f 62 61 72 72 61 7c } //00 00 
		$a_00_8 = {5d 04 00 } //00 d7 
	condition:
		any of ($a_*)
 
}