
rule TrojanSpy_Win32_Bancos_QQ{
	meta:
		description = "TrojanSpy:Win32/Bancos.QQ,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 42 61 6e 63 6f 42 72 61 73 69 6c 5c 62 62 5c 6c 6f 67 69 6e 70 66 65 2e 62 62 5f 61 72 71 75 69 76 6f 73 } //1 C:\BancoBrasil\bb\loginpfe.bb_arquivos
		$a_01_1 = {5b 62 62 2e 63 6f 6d 2e 62 72 5d 20 2d 20 47 65 72 65 6e 63 69 61 64 6f 72 20 46 69 6e 61 6e 63 65 69 72 6f } //1 [bb.com.br] - Gerenciador Financeiro
		$a_01_2 = {43 3a 5c 42 61 6e 63 6f 42 72 61 73 69 6c 5c 62 62 5c 44 44 41 2e 65 78 65 } //1 C:\BancoBrasil\bb\DDA.exe
		$a_01_3 = {54 49 64 46 54 50 54 72 61 6e 73 66 65 72 54 79 70 65 } //1 TIdFTPTransferType
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}