
rule Ransom_Win64_Filecoder_PAQ_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PAQ!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2c 20 61 6e 64 20 79 6f 75 72 20 73 65 6e 73 69 74 69 76 65 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 65 78 66 69 6c 74 72 61 74 65 64 } //2 Your files have been encrypted, and your sensitive data has been exfiltrated
		$a_01_1 = {57 68 61 74 20 64 72 69 76 65 20 64 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 65 6e 63 72 79 70 74 } //2 What drive do you want to encrypt
		$a_01_2 = {54 6f 20 75 6e 6c 6f 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 20 61 6e 64 20 70 72 65 76 65 6e 74 20 70 75 62 6c 69 63 20 64 69 73 63 6c 6f 73 75 72 65 20 6f 66 20 64 61 74 61 20 61 20 70 61 79 6d 65 6e 74 20 69 73 20 72 65 71 75 69 72 65 64 } //2 To unlock your files and prevent public disclosure of data a payment is required
		$a_01_3 = {65 6e 63 76 32 2e 70 64 62 } //1 encv2.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}