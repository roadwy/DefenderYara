
rule TrojanSpy_Win32_Qipi_A{
	meta:
		description = "TrojanSpy:Win32/Qipi.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {45 4d 41 49 4c 53 20 45 4d 20 4d 41 53 53 41 20 44 41 20 4c 49 53 54 41 20 44 45 20 43 4f 4e 54 41 54 4f 53 20 44 4f 20 4d 53 4e 20 56 2d 35 2e 30 30 30 } //03 00  EMAILS EM MASSA DA LISTA DE CONTATOS DO MSN V-5.000
		$a_01_1 = {70 72 6f 67 72 61 6d 73 5c 73 74 61 72 74 75 70 5c 6a 6d 73 64 62 72 63 66 67 2e 65 78 65 } //02 00  programs\startup\jmsdbrcfg.exe
		$a_01_2 = {74 6d 61 74 69 76 61 6d 73 6e 54 69 6d 65 72 } //01 00  tmativamsnTimer
		$a_01_3 = {67 73 6d 74 70 31 38 35 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } //00 00  gsmtp185.google.com
	condition:
		any of ($a_*)
 
}