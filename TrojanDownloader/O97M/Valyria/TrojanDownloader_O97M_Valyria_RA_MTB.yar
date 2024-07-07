
rule TrojanDownloader_O97M_Valyria_RA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Valyria.RA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 72 61 6e 73 66 76 77 35 38 35 7a 62 68 72 2e 73 68 2f 67 76 77 35 38 35 7a 62 68 74 2f 73 70 6d 76 77 35 38 35 7a 62 68 6c 36 } //1 transfvw585zbhr.sh/gvw585zbht/spmvw585zbhl6
		$a_01_1 = {62 66 73 73 32 31 61 70 70 64 62 66 73 73 32 31 61 74 62 66 73 73 32 31 61 5c 72 6f 62 66 73 73 32 31 61 6d 69 6e 67 5c 62 65 72 6f 73 2e 6c 6e 6b } //1 bfss21appdbfss21atbfss21a\robfss21aming\beros.lnk
		$a_01_2 = {6d 6e 6f 74 65 70 61 64 2e 65 78 65 } //1 mnotepad.exe
		$a_01_3 = {67 6f 64 6b 6e 6f 77 73 } //1 godknows
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}