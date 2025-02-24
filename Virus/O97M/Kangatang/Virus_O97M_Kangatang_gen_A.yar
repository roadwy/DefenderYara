
rule Virus_O97M_Kangatang_gen_A{
	meta:
		description = "Virus:O97M/Kangatang.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {61 70 70 6c 69 63 61 74 69 6f 6e 2e 6f 6e 73 68 65 65 74 61 63 74 69 76 61 74 65 3d 22 6d 79 70 65 72 73 6f 6e 6e 65 6c [0-04] 2e 78 6c 73 21 61 6c 6c 6f 63 61 74 65 64 22 } //1
		$a_01_1 = {69 66 61 63 74 69 76 65 77 6f 72 6b 62 6f 6f 6b 2e 73 68 65 65 74 73 28 31 29 2e 6e 61 6d 65 3c 3e 22 6b 61 6e 67 61 74 61 6e 67 22 74 68 65 6e 61 70 70 6c 69 63 61 74 69 6f 6e 2e 73 63 72 65 65 6e 75 70 64 61 74 69 6e 67 } //1 ifactiveworkbook.sheets(1).name<>"kangatang"thenapplication.screenupdating
		$a_01_2 = {74 68 69 73 77 6f 72 6b 62 6f 6f 6b 2e 73 68 65 65 74 73 28 22 6b 61 6e 67 61 74 61 6e 67 22 29 2e 63 6f 70 79 62 65 66 6f 72 65 3a 3d 61 63 74 69 76 65 77 6f 72 6b 62 6f 6f 6b 2e 73 68 65 65 74 73 28 31 29 61 63 74 69 76 65 77 6f 72 6b 62 6f 6f 6b 2e 73 68 65 65 74 73 28 63 75 72 72 65 6e 74 73 68 29 2e 73 65 6c 65 63 74 61 70 70 6c 69 63 61 74 69 6f 6e 2e 73 63 72 65 65 6e 75 70 64 61 74 69 6e 67 3d 74 72 75 65 65 6e 64 69 66 65 6e 64 73 75 62 } //1 thisworkbook.sheets("kangatang").copybefore:=activeworkbook.sheets(1)activeworkbook.sheets(currentsh).selectapplication.screenupdating=trueendifendsub
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}