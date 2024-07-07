
rule TrojanDownloader_O97M_Donoff_ARR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.ARR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 67 72 61 6d 57 36 34 33 32 24 } //1 ProgramW6432$
		$a_01_1 = {5c 5c 53 79 73 57 4f 57 36 34 5c 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 \\SysWOW64\\rundll32.exe
		$a_80_2 = {55 00 ac 00 73 00 ac 00 65 00 ac 00 72 00 ac 00 2d 00 ac 00 41 00 ac 00 67 00 ac 00 65 00 ac 00 6e 00 ac 00 74 00 ac 00 3a 00 ac 00 20 00 ac 00 4d 00 ac 00 6f 00 ac 00 7a 00 ac 00 69 00 ac 00 6c 00 ac 00 6c 00 ac 00 61 00 } //U  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}