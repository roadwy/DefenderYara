
rule Worm_Win32_Autorun_JV{
	meta:
		description = "Worm:Win32/Autorun.JV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5b 00 41 00 55 00 54 00 4f 00 52 00 55 00 4e 00 5d 00 } //1 [AUTORUN]
		$a_00_1 = {69 00 6e 00 66 00 5c 00 64 00 72 00 76 00 69 00 6e 00 64 00 65 00 78 00 2e 00 69 00 6e 00 66 00 } //1 inf\drvindex.inf
		$a_01_2 = {f5 00 00 00 00 6c 58 ff 1b 1d 00 2a 23 20 ff 1b 17 00 2a 46 48 ff } //1
		$a_01_3 = {f5 27 00 00 00 6c 2c ff 1b 7e 00 2a 23 24 ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}