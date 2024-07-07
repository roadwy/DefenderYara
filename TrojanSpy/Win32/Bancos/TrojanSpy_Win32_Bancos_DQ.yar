
rule TrojanSpy_Win32_Bancos_DQ{
	meta:
		description = "TrojanSpy:Win32/Bancos.DQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 47 62 50 6c 75 67 69 6e 5c 67 62 78 2e 73 79 73 } //1 C:\Arquivos de programas\GbPlugin\gbx.sys
		$a_80_2 = {52 65 6d 6f 76 65 72 44 65 50 6c 75 67 } //RemoverDePlug  1
		$a_80_3 = {52 65 6d 6f 76 65 64 6f 72 7a 61 6f } //Removedorzao  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule TrojanSpy_Win32_Bancos_DQ_2{
	meta:
		description = "TrojanSpy:Win32/Bancos.DQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {68 74 74 70 3a 2f 2f 32 30 38 2e 39 38 2e 36 31 2e 38 38 2f 6c 69 73 74 61 2f 77 6f 72 6d 32 2e 70 68 70 } //1 http://208.98.61.88/lista/worm2.php
		$a_01_2 = {66 74 70 54 72 61 6e 73 66 65 72 } //1 ftpTransfer
		$a_01_3 = {54 6f 3a 20 00 00 00 00 ff ff ff ff 06 00 00 00 46 72 6f 6d 3a 20 00 00 ff ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}