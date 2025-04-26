
rule TrojanSpy_Win32_Banpaes_gen_A{
	meta:
		description = "TrojanSpy:Win32/Banpaes.gen!A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {ff ff ff ff 11 00 00 00 73 6d 74 70 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 00 00 00 } //1
		$a_01_1 = {ff ff ff ff 19 00 00 00 73 6d 74 70 2e 73 65 67 6d 65 6e 74 61 63 61 6f 6c 69 6e 75 78 2e 6e 65 74 00 00 00 } //1
		$a_01_2 = {63 65 72 74 69 66 69 63 61 64 6f 20 64 69 67 69 74 61 6c 2e } //1 certificado digital.
		$a_01_3 = {64 65 76 65 20 6d 61 6e 74 65 72 20 65 73 73 65 20 61 72 71 75 69 76 6f 20 65 6d 20 6d } //1 deve manter esse arquivo em m
		$a_01_4 = {49 6e 66 6f 72 6d 61 6d 6f 73 20 71 75 65 20 70 61 72 61 20 72 65 61 6c 69 7a 61 72 20 61 20 61 74 75 61 6c 69 7a 61 } //1 Informamos que para realizar a atualiza
		$a_01_5 = {63 6f 6e 65 63 74 61 64 6f 20 61 20 69 6e 74 65 72 6e 65 74 2e } //1 conectado a internet.
		$a_01_6 = {41 74 75 61 6c 69 7a 61 6e 64 6f 2e 2e 2e 41 67 75 61 72 64 65 2e 2e 2e } //1 Atualizando...Aguarde...
		$a_01_7 = {52 75 6e 74 69 6d 65 20 65 72 72 6f 72 20 20 20 20 20 61 74 20 30 30 30 30 30 30 30 30 } //1 Runtime error     at 00000000
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}