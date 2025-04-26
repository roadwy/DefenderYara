
rule TrojanSpy_Win32_Agent_KA{
	meta:
		description = "TrojanSpy:Win32/Agent.KA,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {52 43 50 54 20 54 4f } //1 RCPT TO
		$a_01_2 = {4d 41 49 4c 20 46 52 4f 4d } //1 MAIL FROM
		$a_01_3 = {77 65 62 70 6f 70 2e 78 70 67 2e 63 6f 6d 2e 62 72 2f 43 6f 6e 66 69 67 75 72 61 63 6f 65 73 2e 69 6e 69 } //1 webpop.xpg.com.br/Configuracoes.ini
		$a_01_4 = {6e 65 74 73 68 2e 65 78 65 } //1 netsh.exe
		$a_01_5 = {57 53 41 41 73 79 6e 63 47 65 74 48 6f 73 74 42 79 4e 61 6d 65 } //1 WSAAsyncGetHostByName
		$a_01_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}