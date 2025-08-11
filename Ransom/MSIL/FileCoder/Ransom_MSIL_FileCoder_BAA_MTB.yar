
rule Ransom_MSIL_FileCoder_BAA_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 } //1 RansomwareEncryption
		$a_01_1 = {2e 00 72 00 61 00 70 00 65 00 64 00 } //1 .raped
		$a_01_2 = {44 00 69 00 73 00 70 00 6c 00 61 00 79 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 4e 00 6f 00 74 00 65 00 } //1 DisplayRansomNote
		$a_01_3 = {72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //1 readme.txt
		$a_01_4 = {4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 48 00 65 00 6c 00 70 00 65 00 72 00 2e 00 64 00 61 00 74 00 } //1 MalwareHelper.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}