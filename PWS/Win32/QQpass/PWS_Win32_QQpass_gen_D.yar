
rule PWS_Win32_QQpass_gen_D{
	meta:
		description = "PWS:Win32/QQpass.gen!D,SIGNATURE_TYPE_PEHSTR,18 00 18 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {78 69 6e 67 64 65 73 68 69 68 6f 75 } //0a 00  xingdeshihou
		$a_01_1 = {74 69 61 6e 68 65 69 68 65 69 74 69 6f 6f 74 69 61 6e 74 69 61 6e 64 6f 75 79 61 6f 6e 69 61 69 77 6f 64 } //02 00  tianheiheitiootiantiandouyaoniaiwod
		$a_01_2 = {68 6f 6e 67 77 6f 6e 61 68 73 6f 75 67 65 68 61 6f 78 69 61 6e 67 7a 68 65 79 61 6e 67 } //01 00  hongwonahsougehaoxiangzheyang
		$a_01_3 = {46 53 44 46 53 44 00 00 45 78 70 6c 6f 72 65 72 2e 45 78 65 00 00 00 00 56 65 72 43 4c 53 49 44 2e 65 78 65 } //01 00 
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //00 00  InternetOpenUrlA
	condition:
		any of ($a_*)
 
}