
rule TrojanSpy_Win32_Bancos_AAW{
	meta:
		description = "TrojanSpy:Win32/Bancos.AAW,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 64 69 74 31 4b 65 79 50 72 65 73 73 } //02 00  Edit1KeyPress
		$a_01_1 = {49 6e 73 69 72 61 20 63 6f 72 72 65 74 61 6d 65 6e 74 65 20 6f 20 63 61 6d 70 6f 20 73 6f 6c 69 63 69 74 61 64 6f } //05 00  Insira corretamente o campo solicitado
		$a_01_2 = {6d 61 72 63 6f 73 2e 61 76 69 6c 65 6e 63 6f 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d } //00 00  marcos.avilenco@hotmail.com
	condition:
		any of ($a_*)
 
}