
rule Trojan_AndroidOS_Spynote_K{
	meta:
		description = "Trojan:AndroidOS/Spynote.K,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 6d 6f 62 69 68 6b 2f 76 2f 6b 66 6f 72 6e 69 77 77 73 77 30 3b } //02 00  Lcom/mobihk/v/kforniwwsw0;
		$a_01_1 = {67 2f 63 68 32 2e 79 67 64 79 65 67 70 68 70 3f 73 79 67 64 79 65 67 73 6c 3d } //02 00  g/ch2.ygdyegphp?sygdyegsl=
		$a_01_2 = {79 67 64 79 65 67 68 74 74 70 3a 79 67 64 79 65 67 2f 2f 77 77 77 79 67 64 79 65 67 2e 6d 6f 62 69 79 67 64 79 65 67 68 6f 6b 2e 6e 79 67 64 79 65 67 65 74 2f 63 68 79 67 64 79 65 } //00 00  ygdyeghttp:ygdyeg//wwwygdyeg.mobiygdyeghok.nygdyeget/chygdye
	condition:
		any of ($a_*)
 
}