
rule Ransom_MSIL_JigsawLocker_C{
	meta:
		description = "Ransom:MSIL/JigsawLocker.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 46 00 69 00 6c 00 65 00 4c 00 69 00 73 00 74 00 2e 00 74 00 78 00 74 00 } //1 EncryptedFileList.txt
		$a_01_1 = {2e 00 70 00 65 00 6e 00 6e 00 79 00 77 00 69 00 73 00 65 00 41 00 } //1 .pennywiseA
		$a_01_2 = {5c 00 44 00 65 00 6c 00 65 00 74 00 65 00 49 00 74 00 73 00 65 00 6c 00 66 00 2e 00 62 00 61 00 74 00 } //1 \DeleteItself.bat
		$a_01_3 = {4e 00 6f 00 74 00 54 00 78 00 74 00 54 00 65 00 73 00 74 00 2e 00 6e 00 6f 00 74 00 74 00 78 00 74 00 } //1 NotTxtTest.nottxt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}