
rule TrojanSpy_Win32_Bancos_AAE{
	meta:
		description = "TrojanSpy:Win32/Bancos.AAE,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //01 00  c:\windows\system32\drivers\etc\hosts
		$a_01_1 = {69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 62 00 61 00 6e 00 6b 00 69 00 6e 00 67 00 2e 00 63 00 61 00 69 00 78 00 61 00 2e 00 67 00 6f 00 76 00 2e 00 62 00 72 00 20 00 23 00 20 00 47 00 62 00 50 00 6c 00 75 00 67 00 75 00 69 00 6e 00 } //01 00  internetbanking.caixa.gov.br # GbPluguin
		$a_01_2 = {63 00 3a 00 5c 00 62 00 6f 00 72 00 6f 00 67 00 76 00 65 00 67 00 61 00 73 00 2e 00 74 00 78 00 74 00 } //00 00  c:\borogvegas.txt
	condition:
		any of ($a_*)
 
}