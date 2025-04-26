
rule TrojanDownloader_Win32_Banload_gen_T{
	meta:
		description = "TrojanDownloader:Win32/Banload.gen!T,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 00 63 00 6d 00 58 00 76 00 59 00 56 00 55 00 64 00 } //1 wcmXvYVUd
		$a_01_1 = {5c 00 6c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //1 \loader\Loader.vbp
		$a_01_2 = {59 00 55 00 23 00 4d 00 4b 00 25 00 46 00 52 00 54 00 47 00 26 00 56 00 42 00 47 00 54 00 59 00 55 00 2a 00 57 00 49 00 28 00 4c 00 4c 00 46 00 40 00 49 00 41 00 53 00 57 00 21 00 4f 00 4c 00 } //1 YU#MK%FRTG&VBGTYU*WI(LLF@IASW!OL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}