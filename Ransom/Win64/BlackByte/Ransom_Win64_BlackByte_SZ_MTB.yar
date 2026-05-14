
rule Ransom_Win64_BlackByte_SZ_MTB{
	meta:
		description = "Ransom:Win64/BlackByte.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 65 6e 74 6c 65 6d 65 6e 2c 20 79 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Gentlemen, your network has been encrypted
		$a_01_1 = {6d 6f 64 69 66 69 63 61 74 69 6f 6e 20 6f 66 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 77 69 6c 6c 20 6d 61 6b 65 20 72 65 63 6f 76 65 72 79 20 69 6d 70 6f 73 73 69 62 6c 65 } //1 modification of encrypted files will make recovery impossible
		$a_01_2 = {57 65 20 68 61 76 65 20 65 78 66 69 6c 74 72 61 74 65 64 20 61 6c 6c 20 79 6f 75 72 20 63 6f 6e 66 69 64 65 6e 74 69 61 6c 20 61 6e 64 20 62 75 73 69 6e 65 73 73 20 64 61 74 61 } //1 We have exfiltrated all your confidential and business data
		$a_01_3 = {4f 6e 6c 79 20 77 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 64 61 74 61 } //1 Only we can decrypt your data
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}