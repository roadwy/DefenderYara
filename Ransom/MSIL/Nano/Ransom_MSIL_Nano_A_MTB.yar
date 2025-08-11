
rule Ransom_MSIL_Nano_A_MTB{
	meta:
		description = "Ransom:MSIL/Nano.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {64 72 6f 70 52 61 6e 73 6f 6d 4e 6f 74 65 } //1 dropRansomNote
		$a_81_1 = {4e 61 6e 6f 5f 4e 6f 74 65 2e 74 78 74 } //1 Nano_Note.txt
		$a_81_2 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 4e 61 6e 6f 20 52 61 6e 73 6f 6d 77 61 72 65 2c 20 6d 65 61 6e 69 6e 67 20 74 68 61 74 20 79 6f 75 72 20 64 61 74 61 20 69 73 20 65 6e 63 72 79 70 74 65 64 } //1 Your files are encrypted by Nano Ransomware, meaning that your data is encrypted
		$a_81_3 = {79 6f 75 20 77 69 6c 6c 20 6e 65 65 64 20 74 6f 20 70 61 79 20 66 6f 72 20 69 74 } //1 you will need to pay for it
		$a_81_4 = {54 68 65 20 70 61 79 6d 65 6e 74 20 69 73 20 61 63 63 65 70 74 65 64 20 6f 6e 6c 79 20 69 6e 20 42 69 74 63 6f 69 6e } //1 The payment is accepted only in Bitcoin
		$a_81_5 = {59 6f 75 20 73 68 6f 75 6c 64 20 72 65 63 65 69 76 65 20 61 20 72 65 70 6c 79 20 66 72 6f 6d 20 74 68 65 20 73 61 6d 65 20 61 64 64 72 65 73 73 2c 20 6f 6e 6c 79 20 74 68 69 73 20 74 69 6d 65 20 77 69 74 68 20 61 20 64 65 63 72 79 70 74 69 6f 6e 20 4b 65 79 } //1 You should receive a reply from the same address, only this time with a decryption Key
		$a_81_6 = {64 65 63 72 79 70 74 65 64 } //1 decrypted
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}