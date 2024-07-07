
rule Ransom_Java_Filecoder_A_MTB{
	meta:
		description = "Ransom:Java/Filecoder.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 6c 69 63 6f 63 72 79 70 74 6f 72 2f 43 6c 69 63 6f 63 72 79 70 74 6f 72 } //1 clicocryptor/Clicocryptor
		$a_02_1 = {68 74 74 70 3a 2f 2f 90 02 21 2e 6f 6e 69 6f 6e 90 00 } //1
		$a_00_2 = {66 69 6c 65 5f 6c 69 73 74 5f 74 6f 5f 65 6e 63 72 79 70 74 } //1 file_list_to_encrypt
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}