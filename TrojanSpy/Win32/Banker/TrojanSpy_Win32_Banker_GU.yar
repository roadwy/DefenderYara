
rule TrojanSpy_Win32_Banker_GU{
	meta:
		description = "TrojanSpy:Win32/Banker.GU,SIGNATURE_TYPE_PEHSTR_EXT,31 00 31 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {46 50 55 4d 61 73 6b 56 61 6c 75 65 } //0a 00  FPUMaskValue
		$a_01_1 = {53 65 72 76 69 63 65 73 20 48 6f 74 } //01 00  Services Hot
		$a_01_2 = {53 65 6e 68 61 20 70 6f 73 73 75 69 20 74 61 6d 61 6e 68 6f 20 69 6e 76 } //01 00  Senha possui tamanho inv
		$a_01_3 = {57 69 6e 64 6f 77 73 20 4c 69 76 65 20 4d 65 73 73 65 6e 67 65 72 } //01 00  Windows Live Messenger
		$a_01_4 = {68 74 74 70 3a 2f 2f 6d 61 69 6c 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //01 00  http://mail.terra.com.br
		$a_01_5 = {67 6f 6f 67 6c 65 2e 63 6f 6d 2f 61 63 63 6f 75 6e 74 73 2f 53 65 72 76 69 63 65 4c 6f 67 69 6e 3f 73 65 72 76 69 63 65 3d 6d 61 69 6c } //05 00  google.com/accounts/ServiceLogin?service=mail
		$a_01_6 = {57 53 41 53 65 74 53 65 72 76 69 63 65 57 } //05 00  WSASetServiceW
		$a_01_7 = {57 53 41 52 65 63 76 45 78 } //05 00  WSARecvEx
		$a_01_8 = {54 57 65 62 42 72 6f 77 73 65 72 44 6f 63 75 6d 65 6e 74 43 6f 6d 70 6c 65 74 65 } //05 00  TWebBrowserDocumentComplete
		$a_01_9 = {4f 6e 44 6f 77 6e 6c 6f 61 64 43 6f 6d 70 6c 65 74 65 } //05 00  OnDownloadComplete
		$a_01_10 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}