
rule TrojanSpy_Win32_Bancos_AGY{
	meta:
		description = "TrojanSpy:Win32/Bancos.AGY,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 37 48 71 53 37 43 77 42 6f 7a 74 54 74 53 6b 53 73 35 6b 54 36 35 6b 50 36 4c 6f 52 63 4c 71 42 63 44 6c 52 49 76 59 } //01 00 
		$a_01_1 = {42 72 61 64 65 73 63 6f 20 49 6e 74 65 72 6e 65 74 20 42 61 6e 6b 69 6e 67 } //01 00 
		$a_01_2 = {5c 54 79 70 65 64 55 52 4c 53 } //01 00 
		$a_01_3 = {44 69 67 69 74 65 20 73 75 61 20 73 65 6e 68 61 20 64 65 } //00 00 
	condition:
		any of ($a_*)
 
}