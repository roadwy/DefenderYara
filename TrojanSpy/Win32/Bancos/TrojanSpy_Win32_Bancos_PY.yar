
rule TrojanSpy_Win32_Bancos_PY{
	meta:
		description = "TrojanSpy:Win32/Bancos.PY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 70 65 74 73 2e 70 68 70 } //01 00  /pets.php
		$a_01_1 = {62 61 6e 6e 65 72 61 6e 75 6e 63 69 6f 2e 73 77 66 } //01 00  banneranuncio.swf
		$a_01_2 = {42 43 50 3e 3e 3e 20 2d 20 57 69 6e 64 6f 77 73 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //01 00  BCP>>> - Windows Internet Explorer
		$a_01_3 = {42 61 6e 63 6f 20 64 65 } //00 00  Banco de
	condition:
		any of ($a_*)
 
}