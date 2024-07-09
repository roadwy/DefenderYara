
rule TrojanSpy_Win32_Bancos_ACC{
	meta:
		description = "TrojanSpy:Win32/Bancos.ACC,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_03_0 = {03 c6 b9 ff 00 00 00 99 f7 f9 8b da 8b 45 ?? 3b 45 ?? 7d 05 ff 45 ?? eb 07 c7 45 ?? 01 00 00 00 83 f3 } //5
		$a_00_1 = {62 00 74 00 6e 00 5f 00 74 00 65 00 6e 00 74 00 61 00 72 00 5f 00 6e 00 6f 00 76 00 2e 00 67 00 69 00 66 00 } //1 btn_tentar_nov.gif
		$a_00_2 = {73 00 65 00 6e 00 68 00 61 00 } //1 senha
		$a_01_3 = {45 44 54 73 65 6e 68 61 34 4b 65 79 50 72 65 73 73 } //1 EDTsenha4KeyPress
		$a_01_4 = {21 21 21 21 3d 3e 4d 2d 53 2d 4e 3c 3d 21 21 21 21 } //1 !!!!=>M-S-N<=!!!!
		$a_01_5 = {69 6d 67 5f 65 6e 74 72 61 72 43 6c 69 63 6b } //1 img_entrarClick
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}