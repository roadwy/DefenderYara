
rule TrojanSpy_Win32_Chaori_A{
	meta:
		description = "TrojanSpy:Win32/Chaori.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 4a 6e 3a 4d 4b 39 67 4d 4b 44 54 45 4b 55 69 4f 36 72 6b 4d 4b 38 } //01 00 
		$a_01_1 = {4e 37 45 3a 50 33 61 68 40 25 51 25 51 6b } //01 00 
		$a_01_2 = {44 6c 62 50 44 4b 39 6a 51 4a 59 2a 4f 25 7c 54 4d 36 48 54 50 37 39 68 4d 25 39 55 4f 4a 35 6c 4b 35 } //01 00 
		$a_01_3 = {44 3a 72 42 49 34 34 54 44 } //00 00 
	condition:
		any of ($a_*)
 
}