
rule TrojanSpy_Win32_Bancos_LT{
	meta:
		description = "TrojanSpy:Win32/Bancos.LT,SIGNATURE_TYPE_PEHSTR_EXT,12 00 11 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 00 00 00 00 14 00 00 00 4f 00 66 00 66 00 69 00 63 00 65 00 5f 00 61 00 70 00 70 00 00 00 00 00 02 00 00 00 5c 00 00 00 14 00 00 00 66 00 72 00 61 00 6d 00 65 00 31 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_1 = {77 00 77 00 77 00 2e 00 68 00 73 00 62 00 63 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00 
		$a_00_2 = {62 00 72 00 61 00 64 00 65 00 73 00 63 00 6f 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00 
		$a_00_3 = {77 00 77 00 77 00 2e 00 6e 00 6f 00 73 00 73 00 61 00 63 00 61 00 69 00 78 00 61 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00 
		$a_00_4 = {77 00 77 00 77 00 2e 00 6f 00 72 00 6b 00 75 00 74 00 2e 00 63 00 6f 00 6d 00 } //05 00 
		$a_00_5 = {64 72 6f 70 72 69 63 6b 68 61 72 64 31 33 40 67 6d 61 69 6c 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}