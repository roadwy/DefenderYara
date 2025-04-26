
rule Ransom_MSIL_FileCoder_SO_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {5c 44 65 73 6b 74 6f 70 5c 59 4f 55 2d 42 45 54 54 45 52 2d 52 45 41 44 4d 45 2e 74 78 74 } //2 \Desktop\YOU-BETTER-README.txt
		$a_81_1 = {48 61 68 61 20 2d 20 41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 21 } //2 Haha - All your files have been encrypted!!
		$a_81_2 = {4e 65 77 45 6e 63 72 79 70 74 41 70 70 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 NewEncryptApp.Properties.Resources
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}