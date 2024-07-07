
rule TrojanSpy_Win32_Banker_JC{
	meta:
		description = "TrojanSpy:Win32/Banker.JC,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {47 65 72 65 6e 63 69 61 64 6f 72 20 46 69 6e 61 6e 63 65 69 72 6f } //1 Gerenciador Financeiro
		$a_01_2 = {2d 2d 2d 37 63 66 38 37 32 32 34 64 32 30 32 30 61 } //1 ---7cf87224d2020a
		$a_01_3 = {67 65 72 65 6e 63 69 61 64 6f 72 2e 63 61 62 6c 65 2e 6e 75 2f 73 65 61 72 63 68 2e 70 68 70 } //1 gerenciador.cable.nu/search.php
		$a_01_4 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 61 00 61 00 70 00 6a 00 2e 00 62 00 62 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //1 https://aapj.bb.com.br
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}