
rule Trojan_Win32_HtaCrypt_D_MTB{
	meta:
		description = "Trojan:Win32/HtaCrypt.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_81_0 = {59 4f 55 52 20 43 4f 4d 50 41 4e 59 20 4e 45 54 57 4f 52 4b 20 48 41 53 20 42 45 45 4e 20 48 41 43 4b 45 44 } //1 YOUR COMPANY NETWORK HAS BEEN HACKED
		$a_81_1 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 All your important files have been encrypted!
		$a_81_2 = {57 65 20 61 6c 73 6f 20 67 61 74 68 65 72 65 64 20 68 69 67 68 6c 79 20 63 6f 6e 66 69 64 65 6e 74 69 61 6c 2f 70 65 72 73 6f 6e 61 6c 20 64 61 74 61 } //1 We also gathered highly confidential/personal data
		$a_81_3 = {46 69 6c 65 73 20 61 72 65 20 61 6c 73 6f 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 73 74 6f 72 65 64 20 73 65 63 75 72 65 6c 79 } //1 Files are also encrypted and stored securely
		$a_81_4 = {41 6c 6c 20 64 61 74 61 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 73 20 77 69 6c 6c 20 72 65 6d 61 69 6e 20 65 6e 63 72 79 70 74 65 64 20 66 6f 72 65 76 65 72 } //1 All data on your computers will remain encrypted forever
		$a_81_5 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 73 61 66 65 21 20 4f 6e 6c 79 20 6d 6f 64 69 66 69 65 64 } //1 Your files are safe! Only modified
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=4
 
}