
rule TrojanSpy_Win32_Bancos_AGM{
	meta:
		description = "TrojanSpy:Win32/Bancos.AGM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 75 74 74 6f 6e 33 43 6c 69 63 6b } //01 00  Button3Click
		$a_01_1 = {48 67 65 74 65 6c 65 6d 65 6e 74 62 79 69 64 } //01 00  Hgetelementbyid
		$a_01_2 = {6d 6f 7a 69 6c 6c 61 20 66 69 72 65 66 6f 78 } //01 00  mozilla firefox
		$a_01_3 = {74 6d 72 42 75 73 63 61 4d 53 4e 54 69 6d 65 72 } //01 00  tmrBuscaMSNTimer
		$a_01_4 = {74 6d 72 4f 63 75 6c 74 61 49 45 } //00 00  tmrOcultaIE
	condition:
		any of ($a_*)
 
}