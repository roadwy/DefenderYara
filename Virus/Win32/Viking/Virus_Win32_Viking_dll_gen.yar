
rule Virus_Win32_Viking_dll_gen{
	meta:
		description = "Virus:Win32/Viking.dll.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {e3 ba dc b1 ae f4 f8 f4 00 } //1
		$a_01_1 = {d5 d2 cc c4 ef f7 ee ec ef e1 e4 d4 ef c6 e9 ec e5 c1 00 } //2
		$a_01_2 = {f3 ef e6 f4 f7 e1 f2 e5 dc ed e9 } //1
		$a_01_3 = {00 ae e5 f8 e5 00 } //1
		$a_01_4 = {d5 d2 cc cd cf ce ae c4 cc cc 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}