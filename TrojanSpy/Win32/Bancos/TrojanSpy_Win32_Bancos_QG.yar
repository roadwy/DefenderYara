
rule TrojanSpy_Win32_Bancos_QG{
	meta:
		description = "TrojanSpy:Win32/Bancos.QG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 03 00 "
		
	strings :
		$a_03_0 = {84 c0 75 3c 8b 87 90 01 04 66 be eb ff e8 90 01 04 8d 45 f8 ba 90 01 04 e8 90 01 04 8b 55 f8 8b 87 90 01 04 8b 80 90 01 04 8b 08 ff 51 74 90 00 } //01 00 
		$a_01_1 = {63 6f 6d 70 75 74 61 64 6f 72 3d 00 } //01 00 
		$a_01_2 = {75 73 75 61 72 69 6f 3d 00 } //01 00 
		$a_01_3 = {73 68 64 5f 66 69 73 69 63 6f 3d 00 } //01 00 
		$a_01_4 = {73 68 64 5f 66 69 72 6d 77 61 72 65 3d 00 } //01 00 
		$a_01_5 = {70 61 67 5f 69 6e 69 63 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}