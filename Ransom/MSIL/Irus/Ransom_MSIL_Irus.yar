
rule Ransom_MSIL_Irus{
	meta:
		description = "Ransom:MSIL/Irus,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 00 30 00 33 00 63 00 61 00 70 00 78 00 32 00 78 00 2e 00 65 00 78 00 65 00 } //4 \03capx2x.exe
		$a_01_1 = {5c 00 53 00 75 00 72 00 69 00 2e 00 65 00 78 00 65 00 } //4 \Suri.exe
		$a_81_2 = {49 66 20 79 6f 75 20 72 65 6d 6f 76 65 20 6d 65 20 2c 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 74 } //4 If you remove me , all your files will be deletet
		$a_81_3 = {53 75 72 69 50 72 6f 74 65 63 74 6f 72 28 44 6f 6e 27 74 20 72 65 6d 6f 76 65 29 } //4 SuriProtector(Don't remove)
		$a_01_4 = {43 3a 5c 55 73 65 72 73 5c 4d 75 6c 74 69 5c 44 65 73 6b 74 6f 70 5c 54 75 74 74 69 20 69 20 6d 69 65 69 20 70 72 6f 67 65 74 74 69 5c 56 42 2e 4e 45 54 5c 57 69 6e 64 6f 77 73 41 70 70 31 5c 57 69 6e 64 6f 77 73 41 70 70 31 5c 6f 62 6a 5c 44 65 62 75 67 5c 57 69 6e 64 6f 77 73 41 70 70 31 2e 70 64 62 } //4 C:\Users\Multi\Desktop\Tutti i miei progetti\VB.NET\WindowsApp1\WindowsApp1\obj\Debug\WindowsApp1.pdb
		$a_01_5 = {67 65 74 5f 53 75 72 69 50 72 6f 74 65 63 74 6f 72 } //2 get_SuriProtector
		$a_01_6 = {73 65 74 5f 53 75 72 69 50 72 6f 74 65 63 74 6f 72 } //2 set_SuriProtector
		$a_01_7 = {6d 5f 53 75 72 69 50 72 6f 74 65 63 74 6f 72 } //2 m_SuriProtector
		$a_01_8 = {57 69 6e 64 6f 77 73 41 70 70 31 2e 53 75 72 69 50 72 6f 74 65 63 74 6f 72 2e 72 65 73 6f 75 72 63 65 73 } //2 WindowsApp1.SuriProtector.resources
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_81_2  & 1)*4+(#a_81_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=24
 
}