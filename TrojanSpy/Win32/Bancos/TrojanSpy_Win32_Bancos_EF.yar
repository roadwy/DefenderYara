
rule TrojanSpy_Win32_Bancos_EF{
	meta:
		description = "TrojanSpy:Win32/Bancos.EF,SIGNATURE_TYPE_PEHSTR,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {5c 69 65 75 73 65 2e 65 78 65 00 00 } //10
		$a_01_2 = {76 65 69 73 20 6e 6f 20 4d 6f 6d 65 6e 74 6f 21 } //1 veis no Momento!
		$a_01_3 = {2e 6f 72 67 2f 6f 70 65 6e 2e 6a 70 67 } //1 .org/open.jpg
		$a_01_4 = {53 43 5f 50 4c 55 47 5f 42 54 54 5f 32 } //1 SC_PLUG_BTT_2
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=22
 
}