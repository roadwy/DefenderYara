
rule Ransom_MSIL_Small_D_MTB{
	meta:
		description = "Ransom:MSIL/Small.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_81_1 = {46 69 6c 65 20 69 73 20 61 6c 72 65 61 64 79 20 65 6e 63 72 79 70 74 65 64 } //1 File is already encrypted
		$a_81_2 = {52 75 6e 53 6f 6d 65 41 77 61 72 65 } //1 RunSomeAware
		$a_81_3 = {55 72 67 65 6e 74 20 4e 6f 74 69 63 65 2e 74 78 74 } //1 Urgent Notice.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}