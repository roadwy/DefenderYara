
rule TrojanSpy_Win32_Banker_ANO{
	meta:
		description = "TrojanSpy:Win32/Banker.ANO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 2c 20 50 6f 72 20 66 61 76 6f 72 20 64 69 67 69 74 65 20 6e 6f 76 61 6d 65 6e 74 65 2e } //1 o, Por favor digite novamente.
		$a_01_1 = {42 72 6f 77 73 65 72 20 41 6e 65 78 61 64 6f 3a } //1 Browser Anexado:
		$a_01_2 = {42 2e 41 2e 4e 2e 4b 2e 2d 2e 48 2e 53 2e 42 2e 43 } //1 B.A.N.K.-.H.S.B.C
		$a_01_3 = {45 52 52 4f 3a 20 41 63 72 6f 62 61 74 20 52 65 61 64 65 72 73 20 63 6f 6d 20 64 65 66 65 69 74 6f 2c 20 63 6f 6e 74 61 63 74 65 20 73 65 75 20 72 65 76 65 6e 64 65 64 6f 72 2e } //1 ERRO: Acrobat Readers com defeito, contacte seu revendedor.
		$a_03_4 = {8b 4b 70 ba ?? ?? ?? ?? 8b c6 e8 ee d3 ff ff dd 43 40 d8 1d ?? ?? ?? ?? df e0 9e 76 1f ff 73 44 ff 73 40 8d 55 f8 33 c0 e8 00 62 ff ff 8b 4d f8 ba ?? ?? ?? ?? 8b c6 e8 c1 d3 ff ff 8b 7b 20 85 ff 75 0a 83 7b 1c 00 0f 84 88 00 00 00 83 7b 1c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}