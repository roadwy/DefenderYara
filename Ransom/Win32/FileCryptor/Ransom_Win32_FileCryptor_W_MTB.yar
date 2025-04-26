
rule Ransom_Win32_FileCryptor_W_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 53 4f 46 54 57 41 52 45 5c 4c 75 63 79 } //1 \SOFTWARE\Lucy
		$a_02_1 = {2a 00 2e 00 74 00 78 00 74 00 [0-2f] 2a 00 2e 00 6f 00 64 00 74 00 [0-2f] 2a 00 2e 00 77 00 70 00 73 00 } //1
		$a_02_2 = {2a 2e 74 78 74 [0-2f] 2a 2e 6f 64 74 [0-2f] 2a 2e 77 70 73 } //1
		$a_81_3 = {43 72 79 70 74 6f 6c 6f 63 6b 65 72 } //1 Cryptolocker
		$a_81_4 = {2e 45 6e 63 6f 64 65 } //1 .Encode
		$a_81_5 = {46 69 6c 65 2e 4c 75 73 79 } //1 File.Lusy
		$a_81_6 = {44 43 50 63 72 79 70 74 } //1 DCPcrypt
		$a_81_7 = {44 43 50 62 61 73 65 36 34 } //1 DCPbase64
	condition:
		((#a_81_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=5
 
}