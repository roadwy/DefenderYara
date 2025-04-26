
rule Ransom_MSIL_FileCryptor_PN_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.PN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 67 00 65 00 73 00 68 00 } //1 .gesh
		$a_01_1 = {5c 00 52 00 65 00 63 00 6f 00 76 00 65 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 2e 00 67 00 65 00 73 00 68 00 2e 00 74 00 78 00 74 00 } //1 \Recover Files.gesh.txt
		$a_01_2 = {4f 00 6f 00 6f 00 70 00 73 00 2c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //1 Ooops, your files have been encrypted!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}