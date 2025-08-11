
rule Ransom_MSIL_FafsbCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/FafsbCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 63 00 72 00 70 00 74 00 } //1 .crpt
		$a_01_1 = {49 00 73 00 54 00 65 00 73 00 74 00 54 00 72 00 75 00 65 00 2e 00 74 00 78 00 74 00 } //1 IsTestTrue.txt
		$a_01_2 = {44 00 75 00 6d 00 70 00 53 00 74 00 61 00 63 00 6b 00 2e 00 6c 00 6f 00 67 00 2e 00 74 00 6d 00 70 00 } //1 DumpStack.log.tmp
		$a_01_3 = {5c 48 61 63 6b 65 72 2e 70 64 62 } //2 \Hacker.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}