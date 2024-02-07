
rule TrojanSpy_Win32_Banker_WD{
	meta:
		description = "TrojanSpy:Win32/Banker.WD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {5c 6d 73 6e 6f 62 6a 2e 64 6c 6c 90 02 10 5c 6d 73 6e 70 72 69 6e 74 2e 64 6c 6c 90 00 } //01 00 
		$a_01_1 = {6c 69 73 74 61 68 6f 74 6d 61 69 6c 77 65 63 68 61 6d 40 67 6d 61 69 6c 2e 63 6f 6d } //01 00  listahotmailwecham@gmail.com
		$a_01_2 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 6d 73 6e 5f 6c 69 76 65 72 73 2e 65 78 65 } //01 00  C:\Arquivos de programas\msn_livers.exe
		$a_03_3 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 02 10 6d 73 6e 5f 6c 69 76 65 72 73 90 00 } //01 00 
		$a_01_4 = {73 61 4e 6f 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 07 49 64 53 6f 63 6b 73 } //00 00 
	condition:
		any of ($a_*)
 
}