
rule TrojanSpy_Win32_Banker_AKR{
	meta:
		description = "TrojanSpy:Win32/Banker.AKR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b c8 0f bf c3 99 f7 f9 83 c2 01 0f 80 90 01 01 01 00 00 52 8b 55 08 90 00 } //1
		$a_03_1 = {ff d7 50 b9 50 00 00 00 ff 15 90 01 04 8b 55 90 01 01 50 8d 4d 90 01 01 8b 02 50 51 ff d7 8b 56 90 01 01 50 52 e8 90 00 } //1
		$a_00_2 = {43 6f 64 69 67 6f 53 54 52 } //1 CodigoSTR
		$a_00_3 = {43 00 6f 00 6e 00 73 00 75 00 6c 00 74 00 61 00 20 00 65 00 20 00 41 00 6c 00 74 00 65 00 72 00 61 00 } //1 Consulta e Altera
		$a_00_4 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 61 00 63 00 65 00 73 00 73 00 61 00 50 00 61 00 67 00 69 00 6e 00 61 00 } //1 javascript:acessaPagina
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}