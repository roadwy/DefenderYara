
rule TrojanDownloader_Win32_VB_TT{
	meta:
		description = "TrojanDownloader:Win32/VB.TT,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 79 00 5c 00 50 00 61 00 6e 00 64 00 61 00 2e 00 65 00 78 00 65 00 } //1 C:\windy\Panda.exe
		$a_01_1 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 79 00 5c 00 41 00 76 00 61 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 C:\windy\Avast.exe
		$a_01_2 = {43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 79 00 5c 00 46 00 75 00 6e 00 63 00 6f 00 65 00 73 00 2e 00 64 00 6c 00 6c 00 } //1 C:\windy\Funcoes.dll
		$a_01_3 = {54 00 65 00 73 00 74 00 65 00 20 00 64 00 65 00 20 00 65 00 6e 00 63 00 72 00 69 00 70 00 63 00 74 00 61 00 63 00 61 00 6f 00 } //1 Teste de encripctacao
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}