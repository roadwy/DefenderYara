
rule Trojan_Win64_Filecoder_NIA_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.NIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {2e 45 4e 43 52 59 50 54 } //2 .ENCRYPT
		$a_81_1 = {4f 6f 6f 70 73 2c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 Ooops, your files have been encrypted!
		$a_81_2 = {53 65 6e 64 20 24 31 30 30 30 20 77 6f 72 74 68 20 6f 66 20 4d 6f 6e 65 72 6f 20 74 6f 20 74 68 69 73 20 61 64 64 72 65 73 73 } //1 Send $1000 worth of Monero to this address
		$a_81_3 = {59 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 6c 6f 73 74 20 6f 6e } //1 Your files will be lost on
		$a_81_4 = {52 61 6e 73 6f 6d 57 69 6e 64 6f 77 43 6c 61 73 73 } //1 RansomWindowClass
		$a_81_5 = {45 6e 63 72 79 70 74 65 64 20 4b 65 79 3a } //1 Encrypted Key:
		$a_81_6 = {44 65 63 72 79 70 74 69 6f 6e 20 4b 65 79 3a } //1 Decryption Key:
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}