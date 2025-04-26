
rule Ransom_MSIL_Gorf{
	meta:
		description = "Ransom:MSIL/Gorf,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 72 6f 67 2e 65 78 65 } //2 frog.exe
		$a_01_1 = {64 3a 5c 70 72 6f 6a 65 63 74 5f 6d 69 6e 69 5c 6d 77 61 76 65 5c 66 72 6f 67 5c 66 72 6f 67 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 66 72 6f 67 2e 70 64 62 } //2 d:\project_mini\mwave\frog\frog\obj\Release\frog.pdb
		$a_01_2 = {72 00 75 00 61 00 6d 00 79 00 6c 00 6f 00 76 00 65 00 2e 00 32 00 38 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //2 ruamylove.28@gmail.com
		$a_01_3 = {2e 00 66 00 72 00 6f 00 67 00 } //2 .frog
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}