
rule TrojanSpy_Win32_Bancos_AFS{
	meta:
		description = "TrojanSpy:Win32/Bancos.AFS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 00 6f 00 72 00 74 00 67 00 75 00 63 00 6b 00 6f 00 63 00 33 00 } //01 00 
		$a_01_1 = {6e 00 71 00 79 00 67 00 74 00 7a 00 33 00 34 00 35 00 } //01 00 
		$a_01_2 = {53 00 69 00 7a 00 65 00 3d 00 34 00 30 00 39 00 36 00 3b 00 57 00 6f 00 72 00 6b 00 73 00 74 00 61 00 74 00 69 00 6f 00 6e 00 20 00 49 00 44 00 3d 00 58 00 58 00 58 00 58 00 } //00 00 
	condition:
		any of ($a_*)
 
}