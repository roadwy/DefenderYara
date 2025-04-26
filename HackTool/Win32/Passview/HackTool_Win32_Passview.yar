
rule HackTool_Win32_Passview{
	meta:
		description = "HackTool:Win32/Passview,SIGNATURE_TYPE_PEHSTR,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 31 31 31 31 2e 65 78 65 } //2 11111.exe
		$a_01_1 = {66 6a 34 67 68 67 61 32 33 5f 66 73 61 2e 74 78 74 } //2 fj4ghga23_fsa.txt
		$a_01_2 = {68 68 69 75 65 77 33 33 2e 63 6f 6d 2f } //2 hhiuew33.com/
		$a_01_3 = {5c 52 65 6c 65 61 73 65 5c 52 65 73 6f 75 72 63 65 56 65 72 43 75 72 2e 70 64 62 } //2 \Release\ResourceVerCur.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}