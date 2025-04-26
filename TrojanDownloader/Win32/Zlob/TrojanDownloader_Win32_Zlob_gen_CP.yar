
rule TrojanDownloader_Win32_Zlob_gen_CP{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CP,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_02_0 = {e9 29 6b 9d 69 3e ?? 35 31 b5 e4 1d 31 3d bb 39 f7 ec ea 43 06 15 a3 e8 7e bd 49 ea 69 76 21 ba ba 98 26 c8 } //3
		$a_00_1 = {41 32 38 34 2d 39 44 46 32 37 38 } //2 A284-9DF278
		$a_00_2 = {44 41 45 44 39 32 36 36 } //2 DAED9266
		$a_00_3 = {49 45 20 41 00 } //1
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1) >=6
 
}