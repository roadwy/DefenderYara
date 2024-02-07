
rule TrojanSpy_Win32_Bancos_RM{
	meta:
		description = "TrojanSpy:Win32/Bancos.RM,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  :\autorun.inf
		$a_01_1 = {2e 63 6f 6d 2e 62 72 } //01 00  .com.br
		$a_01_2 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  \Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 48 69 64 64 65 6e 5c 53 48 4f 57 41 4c 4c } //01 00  \SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL
		$a_01_4 = {49 64 53 4d 54 50 31 44 69 73 63 6f 6e 6e 65 63 74 65 64 } //01 00  IdSMTP1Disconnected
		$a_01_5 = {41 55 54 48 20 4c 4f 47 49 4e } //00 00  AUTH LOGIN
	condition:
		any of ($a_*)
 
}