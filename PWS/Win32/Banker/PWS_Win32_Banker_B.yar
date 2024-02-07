
rule PWS_Win32_Banker_B{
	meta:
		description = "PWS:Win32/Banker.B,SIGNATURE_TYPE_PEHSTR,52 00 51 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {49 6e 64 79 20 39 2e 30 30 2e 31 30 } //0a 00  Indy 9.00.10
		$a_01_2 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c } //0a 00  MAIL FROM:<
		$a_01_3 = {73 6d 74 70 2e 69 73 62 74 2e 63 6f 6d 2e 62 72 } //0a 00  smtp.isbt.com.br
		$a_01_4 = {43 65 74 65 6c 65 6d 20 2d 20 42 61 6e 6b 69 6e 67 } //0a 00  Cetelem - Banking
		$a_01_5 = {5b 33 20 44 69 67 69 74 6f 73 5d 2e 2e 2e } //0a 00  [3 Digitos]...
		$a_01_6 = {56 61 6c 69 64 61 64 65 2e 2e 2e } //0a 00  Validade...
		$a_01_7 = {3d 2d 50 49 4e 41 2d 32 30 30 39 20 76 65 6d 20 63 61 72 69 6f 6f 6f 6f 2d 3d } //01 00  =-PINA-2009 vem carioooo-=
		$a_01_8 = {66 65 73 74 61 64 6f 63 6f 6c 6f 6e 6f 31 40 69 73 62 74 2e 63 6f 6d 2e 62 72 } //01 00  festadocolono1@isbt.com.br
		$a_01_9 = {74 68 61 6c 69 78 69 6e 68 61 69 6e 76 69 61 40 69 73 62 74 2e 63 6f 6d 2e 62 72 } //00 00  thalixinhainvia@isbt.com.br
	condition:
		any of ($a_*)
 
}