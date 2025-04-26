
rule Ransom_AndroidOS_CdrCrypt_A_MTB{
	meta:
		description = "Ransom:AndroidOS/CdrCrypt.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 63 6f 64 65 72 43 72 79 70 74 } //2 .coderCrypt
		$a_00_1 = {43 6f 64 65 72 57 61 72 65 20 75 73 65 73 20 61 20 62 61 73 69 63 20 65 6e 63 72 79 70 74 69 6f 6e 20 73 63 72 69 70 74 20 74 6f 20 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 } //1 CoderWare uses a basic encryption script to lock your files
		$a_00_2 = {79 6f 75 20 67 6f 74 20 68 69 74 20 62 79 20 43 6f 64 65 72 57 61 72 65 } //1 you got hit by CoderWare
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}