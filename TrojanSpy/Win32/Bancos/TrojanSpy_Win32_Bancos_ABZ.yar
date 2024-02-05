
rule TrojanSpy_Win32_Bancos_ABZ{
	meta:
		description = "TrojanSpy:Win32/Bancos.ABZ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 74 79 70 65 22 } //01 00 
		$a_01_1 = {41 75 74 6f 43 6f 6e 66 69 67 55 72 6c } //01 00 
		$a_01_2 = {62 75 64 64 79 63 6c 75 62 2e 63 6f 2e 7a 61 2f 78 6d 6c 72 70 63 2f 66 69 6c 65 73 2f 68 74 61 63 65 73 73 } //01 00 
		$a_01_3 = {2f 2e 6c 6f 67 73 2f 69 6e 64 65 78 2e 70 68 70 00 00 6f 70 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}