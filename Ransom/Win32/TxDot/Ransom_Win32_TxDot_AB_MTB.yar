
rule Ransom_Win32_TxDot_AB_MTB{
	meta:
		description = "Ransom:Win32/TxDot.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_81_0 = {52 65 61 64 20 74 68 69 73 20 6d 65 73 73 61 67 65 20 43 41 52 45 46 55 4c 4c 59 20 61 6e 64 20 63 6f 6e 74 61 63 74 20 73 6f 6d 65 6f 6e 65 20 66 72 6f 6d 20 49 54 20 64 65 70 61 72 74 6d 65 6e 74 2e } //1 Read this message CAREFULLY and contact someone from IT department.
		$a_81_1 = {21 54 58 44 4f 54 5f 52 45 41 44 5f 4d 45 21 2e 74 78 74 } //1 !TXDOT_READ_ME!.txt
		$a_81_2 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 73 65 63 75 72 65 6c 79 20 45 4e 43 52 59 50 54 45 44 } //1 Your files are securely ENCRYPTED
		$a_81_3 = {4d 4f 44 49 46 49 43 41 54 49 4f 4e 20 6f 72 20 52 45 4e 41 4d 49 4e 47 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 6d 61 79 20 63 61 75 73 65 20 64 65 63 72 79 70 74 69 6f 6e 20 66 61 69 6c 75 72 65 } //1 MODIFICATION or RENAMING encrypted files may cause decryption failure
		$a_81_4 = {73 6f 20 79 6f 75 20 68 61 76 65 20 6e 6f 20 64 6f 75 62 74 73 20 69 6e 20 70 6f 73 73 69 62 69 6c 69 74 79 20 74 6f 20 72 65 73 74 6f 72 65 20 61 6c 6c 20 66 69 6c 65 73 20 66 72 6f 6d 20 61 6c 6c 20 61 66 66 65 63 74 65 64 20 73 79 73 74 65 6d 73 20 41 4e 59 20 54 49 4d 45 } //1 so you have no doubts in possibility to restore all files from all affected systems ANY TIME
		$a_81_5 = {54 68 65 20 72 65 73 74 20 6f 66 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 61 76 61 69 6c 61 62 6c 65 20 61 66 74 65 72 20 74 68 65 20 50 41 59 4d 45 4e 54 } //1 The rest of data will be available after the PAYMENT
		$a_81_6 = {43 6f 6e 74 61 63 74 20 75 73 20 4f 4e 4c 59 20 69 66 20 79 6f 75 20 6f 66 66 69 63 69 61 6c 6c 79 20 72 65 70 72 65 73 65 6e 74 20 74 68 65 20 77 68 6f 6c 65 20 61 66 66 65 63 74 65 64 20 6e 65 74 77 6f 72 6b } //1 Contact us ONLY if you officially represent the whole affected network
		$a_81_7 = {54 68 65 20 50 52 49 43 45 20 64 65 70 65 6e 64 73 20 6f 6e 20 68 6f 77 20 71 75 69 63 6b 6c 79 20 79 6f 75 20 64 6f 20 69 74 } //1 The PRICE depends on how quickly you do it
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=5
 
}