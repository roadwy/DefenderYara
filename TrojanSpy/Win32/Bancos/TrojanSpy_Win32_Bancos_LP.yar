
rule TrojanSpy_Win32_Bancos_LP{
	meta:
		description = "TrojanSpy:Win32/Bancos.LP,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00 
		$a_01_1 = {50 61 73 73 77 6f 72 64 3d 6d 61 74 72 69 78 35 31 3b 50 65 72 73 69 73 74 20 53 65 63 75 72 69 74 79 20 49 6e 66 6f 3d 54 72 75 65 3b } //01 00 
		$a_01_2 = {63 6f 6e 74 72 6f 6c 65 5f 6d 73 6e 5f 61 75 74 6f 31 } //00 00 
	condition:
		any of ($a_*)
 
}