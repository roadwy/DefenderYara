
rule Ransom_Win32_Somhoveran_C{
	meta:
		description = "Ransom:Win32/Somhoveran.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {ef e5 f0 e5 e7 e0 e3 f0 f3 e7 e8 f8 fc 20 e2 e8 ed e4 e0 20 e4 e0 eb e8 f2 f1 ff 00 } //1
		$a_01_1 = {57 69 6e 64 6f 77 73 20 e7 e0 e1 eb ee ea e8 f0 ee e2 e0 ed 21 00 } //1
		$a_01_2 = {41 6e 74 69 57 69 6e 4c 6f 63 6b 65 72 54 72 61 79 2e 65 78 65 00 } //1
		$a_01_3 = {49 6e 66 6f 72 6d 61 74 69 6f 6e 20 61 62 6f 75 74 20 62 6c 6f 63 6b 69 6e 67 } //1 Information about blocking
		$a_01_4 = {54 6f 20 72 65 6d 6f 76 69 6e 67 20 74 68 65 20 73 79 73 74 65 6d 3a } //1 To removing the system:
		$a_01_5 = {be 3c 00 00 00 99 f7 fe 89 55 f8 8b c1 be 3c 00 00 00 99 f7 fe be 3c 00 00 00 99 f7 fe 89 55 fc 8b c1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}