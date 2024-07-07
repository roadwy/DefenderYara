
rule Ransom_MSIL_FileCryptor_PO_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 5c 00 4b 00 65 00 79 00 73 00 5c 00 40 00 57 00 44 00 33 00 30 00 40 00 2e 00 74 00 78 00 74 00 } //1 \Microsoft\Crypto\Keys\@WD30@.txt
		$a_01_1 = {59 00 6f 00 75 00 72 00 20 00 69 00 6d 00 70 00 6f 00 72 00 74 00 61 00 6e 00 74 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 } //1 Your important files are encrypted.
		$a_01_2 = {5c 57 44 33 30 2e 70 64 62 } //1 \WD30.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}