
rule Trojan_Win32_Matcash_gen_D{
	meta:
		description = "Trojan:Win32/Matcash.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,52 00 4f 00 0a 00 00 14 00 "
		
	strings :
		$a_01_0 = {7b 43 31 42 34 44 45 43 32 2d 32 36 32 33 2d 34 33 38 65 2d 39 43 41 32 2d 43 39 30 34 33 41 42 32 38 35 30 38 7d } //0a 00  {C1B4DEC2-2623-438e-9CA2-C9043AB28508}
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 6f 6f 6c 62 61 72 } //0a 00  Software\Microsoft\Internet Explorer\Toolbar
		$a_01_2 = {54 6f 6f 6c 42 61 72 2e 44 4c 4c } //0a 00  ToolBar.DLL
		$a_01_3 = {55 72 6c 45 73 63 61 70 65 41 } //0a 00  UrlEscapeA
		$a_01_4 = {42 61 6e 64 54 6f 6f 6c 42 61 72 52 65 66 6c 65 63 74 6f 72 43 74 72 6c } //0a 00  BandToolBarReflectorCtrl
		$a_01_5 = {42 61 6e 64 54 6f 6f 6c 42 61 72 43 74 72 6c } //03 00  BandToolBarCtrl
		$a_01_6 = {68 74 74 70 3a 2f 2f 62 61 62 65 6c 66 69 73 68 2e 61 6c 74 61 76 69 73 74 61 2e 63 6f 6d 2f } //03 00  http://babelfish.altavista.com/
		$a_01_7 = {68 74 74 70 3a 2f 2f 66 69 6e 61 6e 63 65 2e 79 61 68 6f 6f 2e 63 6f 6d 2f } //03 00  http://finance.yahoo.com/
		$a_01_8 = {68 74 74 70 3a 2f 2f 63 61 73 69 6e 6f 74 72 6f 70 65 7a 2e 63 6f 6d 2f } //03 00  http://casinotropez.com/
		$a_01_9 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6d 66 6d 2e 63 6f 6d } //00 00  http://www.comfm.com
	condition:
		any of ($a_*)
 
}