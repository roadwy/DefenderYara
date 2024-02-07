
rule TrojanSpy_Win32_Bancos_AKP{
	meta:
		description = "TrojanSpy:Win32/Bancos.AKP,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {c1 e0 06 03 d8 89 5d f0 83 c7 06 83 ff 08 7c 42 83 ef 08 8b cf 8b 5d f0 d3 eb 8b cf b8 01 00 00 00 d3 e0 8b c8 } //01 00 
		$a_00_1 = {49 00 6e 00 66 00 6f 00 72 00 6d 00 65 00 20 00 73 00 65 00 75 00 20 00 49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 63 00 61 00 64 00 6f 00 72 00 20 00 00 00 } //01 00 
		$a_00_2 = {64 00 61 00 74 00 61 00 63 00 61 00 64 00 61 00 73 00 74 00 72 00 6f 00 3d 00 } //01 00  datacadastro=
		$a_00_3 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 } //00 00  password=
	condition:
		any of ($a_*)
 
}