
rule TrojanSpy_Win32_Bancos_AMG{
	meta:
		description = "TrojanSpy:Win32/Bancos.AMG,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 00 6f 00 6e 00 74 00 65 00 69 00 72 00 6f 00 2d 00 6d 00 61 00 72 00 69 00 6e 00 65 00 69 00 64 00 65 00 40 00 75 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00  monteiro-marineide@uol.com.br
		$a_01_1 = {72 00 69 00 63 00 6f 00 6e 00 6f 00 76 00 6f 00 32 00 30 00 31 00 33 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //01 00  riconovo2013@gmail.com
		$a_01_2 = {73 00 6d 00 74 00 70 00 73 00 2e 00 75 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //01 00  smtps.uol.com.br
		$a_01_3 = {53 00 65 00 6e 00 68 00 61 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 42 00 61 00 6e 00 6b 00 69 00 6e 00 67 00 3a 00 } //01 00  Senha Internet Banking:
		$a_01_4 = {48 00 53 00 42 00 43 00 20 00 42 00 61 00 6e 00 6b 00 20 00 42 00 72 00 61 00 73 00 69 00 6c 00 20 00 53 00 2e 00 41 00 2e 00 } //00 00  HSBC Bank Brasil S.A.
	condition:
		any of ($a_*)
 
}