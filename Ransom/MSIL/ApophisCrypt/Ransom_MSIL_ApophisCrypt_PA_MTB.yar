
rule Ransom_MSIL_ApophisCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/ApophisCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 61 00 70 00 6f 00 70 00 } //1 .apop
		$a_01_1 = {41 00 74 00 20 00 74 00 68 00 69 00 73 00 20 00 70 00 6f 00 69 00 6e 00 74 00 2c 00 20 00 61 00 6c 00 6c 00 20 00 6f 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //3 At this point, all of your files are encrypted
		$a_03_2 = {5c 41 70 6f 70 68 69 73 5c [0-08] 5c [0-08] 5c 41 70 6f 70 68 69 73 2e 70 64 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_03_2  & 1)*1) >=5
 
}