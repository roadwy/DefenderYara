
rule Ransom_MSIL_Filecoder_EDK_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.EDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 61 6e 73 6f 6d 65 77 61 72 65 2e 70 73 31 } //1 ransomeware.ps1
		$a_01_1 = {44 4f 20 4e 4f 54 20 69 67 6e 6f 72 65 20 74 68 69 73 20 6d 65 73 73 61 67 65 } //1 DO NOT ignore this message
		$a_01_2 = {79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 6c 6f 73 74 20 66 6f 72 65 76 65 72 21 } //1 your files will be lost forever!
		$a_01_3 = {55 6e 69 4b 65 79 4e 54 2e 65 78 65 } //1 UniKeyNT.exe
		$a_01_4 = {67 65 74 50 61 73 73 77 6f 72 64 } //1 getPassword
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}