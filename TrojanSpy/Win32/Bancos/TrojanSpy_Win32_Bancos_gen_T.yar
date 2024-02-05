
rule TrojanSpy_Win32_Bancos_gen_T{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!T,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 54 32 ff 80 ea 90 01 01 f6 d2 e8 90 09 0b 00 be 90 01 01 00 00 00 8d 45 90 01 01 8b 55 90 00 } //01 00 
		$a_01_1 = {62 62 2e 63 6f 6d } //01 00 
		$a_01_2 = {62 72 61 73 69 6c 2e 63 6f 6d } //01 00 
		$a_01_3 = {5c 69 64 73 79 73 2e 74 78 74 } //01 00 
		$a_01_4 = {40 6c 23 6f 25 67 23 23 25 73 2a 23 23 2a 2f } //01 00 
		$a_01_5 = {23 6e 25 75 2a 52 23 5c 23 6e 23 2a 23 23 23 40 23 23 25 6f } //00 00 
	condition:
		any of ($a_*)
 
}