
rule Backdoor_Win32_Sharat_gen_A{
	meta:
		description = "Backdoor:Win32/Sharat.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 63 00 00 25 63 00 00 25 63 00 00 30 00 00 00 30 00 00 00 77 69 6e 00 } //3
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {2e 25 64 0a 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=6
 
}