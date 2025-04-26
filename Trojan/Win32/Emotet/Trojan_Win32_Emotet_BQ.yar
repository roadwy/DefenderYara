
rule Trojan_Win32_Emotet_BQ{
	meta:
		description = "Trojan:Win32/Emotet.BQ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 65 65 72 68 57 48 57 23 40 31 77 48 4a 6e 45 52 62 52 57 2e 50 64 62 } //3 heerhWHW#@1wHJnERbRW.Pdb
		$a_00_1 = {45 57 48 23 40 31 77 48 4a 6e 45 52 62 52 57 2e 50 64 62 } //3 EWH#@1wHJnERbRW.Pdb
		$a_01_2 = {6e 00 69 00 37 00 3d 00 38 00 68 00 4c 00 4f 00 36 00 6f } //2
		$a_01_3 = {53 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 } //1 S Corpora
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=6
 
}