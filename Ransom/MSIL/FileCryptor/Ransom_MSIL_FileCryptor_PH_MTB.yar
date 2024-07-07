
rule Ransom_MSIL_FileCryptor_PH_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //1 .locked
		$a_01_1 = {41 00 6c 00 6c 00 20 00 46 00 69 00 6c 00 65 00 20 00 49 00 73 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 All File Is Encrypted
		$a_01_2 = {52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 ReadMe.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}