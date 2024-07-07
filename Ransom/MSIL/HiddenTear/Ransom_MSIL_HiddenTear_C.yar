
rule Ransom_MSIL_HiddenTear_C{
	meta:
		description = "Ransom:MSIL/HiddenTear.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {59 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 66 00 69 00 6c 00 65 00 20 00 69 00 73 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 61 00 6e 00 64 00 20 00 63 00 61 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 62 00 65 00 20 00 6f 00 70 00 65 00 6e 00 65 00 64 00 2e 00 49 00 74 00 27 00 73 00 20 00 6e 00 6f 00 20 00 75 00 73 00 65 00 20 00 6c 00 6f 00 6f 00 6b 00 69 00 6e 00 67 00 20 00 61 00 74 00 20 00 66 00 69 00 6c 00 65 00 20 00 65 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 21 00 } //1 Your computer file is encrypted and can not be opened.It's no use looking at file extensions!
		$a_01_1 = {5c 6f 62 6a 5c 44 65 62 75 67 5c 53 63 72 65 65 6e 4c 6f 63 6b 65 72 2e 70 64 62 } //1 \obj\Debug\ScreenLocker.pdb
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}