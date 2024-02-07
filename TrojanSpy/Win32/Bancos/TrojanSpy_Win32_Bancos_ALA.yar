
rule TrojanSpy_Win32_Bancos_ALA{
	meta:
		description = "TrojanSpy:Win32/Bancos.ALA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 74 61 63 74 40 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 31 } //01 00  contact@microsoft.com1
		$a_01_1 = {49 00 6e 00 66 00 6f 00 20 00 4d 00 50 00 53 00 20 00 69 00 6e 00 63 00 } //01 00  Info MPS inc
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 6e 65 32 2e 62 72 61 64 65 73 63 6f 6e 65 74 65 6d 70 72 65 73 61 2e 62 2e 62 72 2f 69 62 70 6a 62 6f 6c 65 74 6f 2f } //01 00  https://www.ne2.bradesconetempresa.b.br/ibpjboleto/
		$a_01_3 = {3e 00 43 00 6c 00 69 00 71 00 75 00 65 00 20 00 61 00 71 00 75 00 69 00 3c 00 2f 00 61 00 3e 00 } //01 00  >Clique aqui</a>
		$a_01_4 = {35 57 69 6e 64 6f 77 73 20 4d 65 6d 6f 72 79 20 44 69 61 67 6e 6f 73 74 69 63 20 74 6f 6f 6c 20 43 6f 6e 74 61 63 74 3a } //00 00  5Windows Memory Diagnostic tool Contact:
		$a_00_5 = {5d 04 00 } //00 ac 
	condition:
		any of ($a_*)
 
}