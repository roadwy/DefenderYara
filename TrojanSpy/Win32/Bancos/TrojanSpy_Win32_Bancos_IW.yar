
rule TrojanSpy_Win32_Bancos_IW{
	meta:
		description = "TrojanSpy:Win32/Bancos.IW,SIGNATURE_TYPE_PEHSTR,55 01 55 01 0c 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //100 explorerbar
		$a_01_2 = {5c 73 76 63 68 6f 73 74 2e 73 63 72 } //100 \svchost.scr
		$a_01_3 = {45 64 69 74 65 64 20 62 79 20 6c 69 6e 75 78 } //10 Edited by linux
		$a_01_4 = {2f 73 63 72 69 70 74 73 2f 65 6e 67 69 6e 65 5f 62 72 70 69 2e 64 6c 6c } //10 /scripts/engine_brpi.dll
		$a_01_5 = {72 61 75 62 65 72 32 40 69 73 62 74 2e 63 6f 6d 2e 62 72 } //10 rauber2@isbt.com.br
		$a_01_6 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //10 UnhookWindowsHookEx
		$a_01_7 = {42 45 43 20 2d 20 42 61 6e 63 6f 20 64 6f 20 45 73 74 61 64 6f 20 64 6f 20 43 65 61 72 } //1 BEC - Banco do Estado do Cear
		$a_01_8 = {49 6e 74 65 72 6e 65 74 20 42 61 6e 6b 69 6e 67 20 43 41 49 58 41 } //1 Internet Banking CAIXA
		$a_01_9 = {47 65 72 65 6e 63 69 61 64 6f 72 20 46 69 6e 61 6e 63 65 69 72 6f } //1 Gerenciador Financeiro
		$a_01_10 = {42 61 6e 63 6f 20 42 72 61 64 65 73 63 6f 20 53 2f 41 } //1 Banco Bradesco S/A
		$a_01_11 = {42 72 61 64 65 73 63 6f 20 49 6e 74 65 72 6e 65 74 20 42 61 6e 6b 69 6e 67 } //1 Bradesco Internet Banking
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=341
 
}