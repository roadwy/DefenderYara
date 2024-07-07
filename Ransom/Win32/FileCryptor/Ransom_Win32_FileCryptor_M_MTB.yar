
rule Ransom_Win32_FileCryptor_M_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {64 65 63 72 79 70 74 20 66 69 6c 65 73 2c 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 70 61 79 } //1 decrypt files, you need to pay
		$a_81_1 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 49 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Your personal fIles are encrypted
		$a_81_2 = {2e 4c 6f 63 6b } //1 .Lock
		$a_81_3 = {43 72 79 70 74 6f 4c 6f 63 6b 65 72 } //1 CryptoLocker
		$a_81_4 = {2f 63 20 64 65 6c 20 43 3a 5c 2a 20 2f 73 20 2f 71 } //1 /c del C:\* /s /q
		$a_81_5 = {50 61 79 6d 65 6e 74 20 69 73 20 61 63 63 65 70 74 65 64 20 6f 6e 6c 79 20 69 6e 20 62 69 74 63 6f 69 6e } //1 Payment is accepted only in bitcoin
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}