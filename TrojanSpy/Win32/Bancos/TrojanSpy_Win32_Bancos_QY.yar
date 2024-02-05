
rule TrojanSpy_Win32_Bancos_QY{
	meta:
		description = "TrojanSpy:Win32/Bancos.QY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 6e 68 61 20 34 44 69 67 69 74 } //01 00 
		$a_01_1 = {62 74 5f 63 6f 6e 66 69 72 6d 61 72 2e 67 69 66 22 20 76 61 6c 75 65 3d 22 43 4f 4e 46 49 52 4d 41 52 } //01 00 
		$a_01_2 = {67 65 74 45 6c 65 6d 65 6e 74 42 79 49 64 28 27 69 6d 67 5f 61 6c 65 72 74 61 27 29 } //01 00 
		$a_01_3 = {73 65 74 50 75 62 6c 69 63 28 6e 5f 49 6e 74 65 72 6e 65 74 42 61 6e 6b 69 6e 67 57 } //00 00 
	condition:
		any of ($a_*)
 
}