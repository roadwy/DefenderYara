
rule TrojanSpy_Win32_Bancos_BA{
	meta:
		description = "TrojanSpy:Win32/Bancos.BA,SIGNATURE_TYPE_PEHSTR,ffffffb9 01 ffffffb9 01 0c 00 00 64 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //64 00  explorerbar
		$a_01_1 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //64 00  CallNextHookEx
		$a_01_2 = {4d 61 6b 69 6e 61 20 69 6e 66 65 63 74 65 64 } //64 00  Makina infected
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_4 = {31 32 33 71 77 65 } //0a 00  123qwe
		$a_01_5 = {62 6f 79 70 72 65 74 6f } //0a 00  boypreto
		$a_01_6 = {53 65 6e 68 61 20 69 6e 74 65 72 6e 65 74 } //0a 00  Senha internet
		$a_01_7 = {49 74 61 75 20 6e 61 73 63 69 6d 65 6e 74 6f } //01 00  Itau nascimento
		$a_01_8 = {6c 6f 67 73 40 61 6d 69 67 6f 73 2e 63 6f 6d 2e 62 72 } //01 00  logs@amigos.com.br
		$a_01_9 = {73 6d 74 70 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //01 00  smtp.terra.com.br
		$a_01_10 = {62 6f 79 70 72 65 74 6f 40 74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //01 00  boypreto@terra.com.br
		$a_01_11 = {61 64 6d 74 64 66 40 79 61 68 6f 6f 2e 63 6f 6d 2e 62 72 } //00 00  admtdf@yahoo.com.br
	condition:
		any of ($a_*)
 
}