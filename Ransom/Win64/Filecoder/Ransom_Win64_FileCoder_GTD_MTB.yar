
rule Ransom_Win64_FileCoder_GTD_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 65 20 68 61 76 65 20 65 6e 63 72 79 70 74 65 64 20 79 6f 75 72 20 64 61 74 61 20 61 6e 64 20 65 78 66 69 6c 74 72 61 74 65 64 20 73 65 6e 73 69 74 69 76 65 20 64 6f 63 75 6d 65 6e 74 73 } //1 We have encrypted your data and exfiltrated sensitive documents
		$a_01_1 = {53 63 72 65 65 6e 73 68 6f 74 20 6f 66 20 6f 74 68 65 72 20 63 75 73 74 6f 6d 65 72 73 20 77 68 6f 20 68 61 76 65 20 70 61 69 64 20 61 6e 64 20 72 65 63 65 69 76 65 64 20 64 65 63 72 79 70 74 69 6f 6e } //1 Screenshot of other customers who have paid and received decryption
		$a_01_2 = {54 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 20 61 6e 64 20 70 72 65 76 65 6e 74 20 70 75 62 6c 69 63 20 64 69 73 63 6c 6f 73 75 72 65 20 6f 66 20 64 6f 63 75 6d 65 6e 74 73 20 61 20 70 61 79 6d 65 6e 74 20 69 6e 20 66 6f 72 6d 20 6f 66 20 63 72 79 70 74 6f 20 63 75 72 72 65 6e 63 79 20 69 73 20 72 65 71 75 69 72 65 64 } //1 To recover your files and prevent public disclosure of documents a payment in form of crypto currency is required
		$a_01_3 = {56 73 73 61 64 6d 69 6e 64 65 6c 65 74 65 73 68 61 64 6f 77 73 2f 61 6c 6c 2f 71 75 69 65 74 } //1 Vssadmindeleteshadows/all/quiet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}