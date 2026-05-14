
rule Ransom_Linux_Encoder_PA_MTB{
	meta:
		description = "Ransom:Linux/Encoder.PA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 73 79 73 74 65 6d 66 69 6c 65 } //1 .systemfile
		$a_01_1 = {66 69 6c 65 20 69 73 20 65 6e 63 72 79 70 74 65 64 } //1 file is encrypted
		$a_01_2 = {25 73 2f 5f 46 49 4c 45 53 5f 45 4e 43 52 59 50 54 45 44 5f 52 45 41 44 4d 45 2e 74 78 74 } //3 %s/_FILES_ENCRYPTED_README.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}