
rule Trojan_Win32_Cridex_GGLM_MTB{
	meta:
		description = "Trojan:Win32/Cridex.GGLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {76 64 69 73 61 62 6c 69 6e 67 67 6f 6e 65 54 66 48 6a 5a } //vdisablinggoneTfHjZ  3
		$a_80_1 = {47 5a 59 77 65 62 76 69 74 65 73 76 6f 61 64 34 } //GZYwebvitesvoad4  3
		$a_80_2 = {4d 6e 43 74 68 65 73 65 44 65 71 61 63 65 69 65 6e 73 47 31 } //MnCtheseDeqaceiensG1  3
		$a_80_3 = {42 65 74 61 74 72 65 65 6b 69 6e 67 33 73 65 65 63 65 73 65 73 6f 65 76 69 6e 67 2e 31 32 33 66 6f 72 58 65 6d 65 74 69 66 } //Betatreeking3seecesesoeving.123forXemetif  3
		$a_80_4 = {43 68 65 65 6d 65 65 68 65 72 69 6e 69 74 69 61 74 65 64 79 37 37 37 37 37 37 62 79 45 } //Cheemeeherinitiatedy777777byE  3
		$a_80_5 = {69 6f 69 6e 6c 6f 69 65 38 52 52 69 65 54 64 54 69 65 54 72 65 76 54 6d 54 6e 65 73 } //ioinloie8RRieTdTieTrevTmTnes  3
		$a_80_6 = {72 65 65 4b 69 72 37 34 72 5a 44 76 72 72 72 69 72 6e } //reeKir74rZDvrrrirn  3
		$a_80_7 = {37 69 6e 72 6e 50 61 65 64 6f 72 61 61 73 4d 61 65 6c 6f 77 73 65 } //7inrnPaedoraasMaelowse  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}