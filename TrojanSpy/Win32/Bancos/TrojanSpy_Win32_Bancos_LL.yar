
rule TrojanSpy_Win32_Bancos_LL{
	meta:
		description = "TrojanSpy:Win32/Bancos.LL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 43 50 54 20 54 4f 3a 3c } //01 00 
		$a_00_1 = {3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 66 6b 69 6e 64 79 73 61 64 76 6e 71 77 33 6e 65 72 61 73 64 66 } //01 00 
		$a_00_2 = {41 70 6c 69 63 61 74 69 76 6f 20 64 65 20 53 65 67 75 72 61 6e c3 a7 61 20 42 72 61 64 65 73 63 6f } //01 00 
		$a_00_3 = {42 4b 62 68 54 62 7e 58 42 4b 21 3b ba 28 c3 } //01 00 
		$a_01_4 = {0f b7 1a 0f bf 31 0f af de 81 c3 00 08 00 00 8b 74 24 24 c1 fb 0c 83 c1 02 89 1e 83 c2 02 83 44 24 24 04 40 83 f8 40 7c d7 } //00 00 
	condition:
		any of ($a_*)
 
}