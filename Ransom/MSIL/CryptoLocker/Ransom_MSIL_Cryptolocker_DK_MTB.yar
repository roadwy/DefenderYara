
rule Ransom_MSIL_Cryptolocker_DK_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 63 72 79 70 74 65 64 } //1 Your personal files have been ecrypted
		$a_81_1 = {43 52 41 43 4b 45 44 20 42 59 20 4d 41 4d 4f 34 33 34 33 37 36 } //1 CRACKED BY MAMO434376
		$a_81_2 = {52 45 41 44 5f 49 54 2e 74 78 74 2e 6c 6f 63 6b 65 64 } //1 READ_IT.txt.locked
		$a_81_3 = {77 61 6e 6e 61 64 69 65 } //1 wannadie
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_Cryptolocker_DK_MTB_2{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,42 00 42 00 0c 00 00 "
		
	strings :
		$a_81_0 = {74 65 73 74 65 72 61 6e 73 77 } //50 testeransw
		$a_81_1 = {64 69 73 6b 5f 65 6e 63 6f 64 65 72 } //50 disk_encoder
		$a_81_2 = {52 61 6e 73 6f 6d 77 61 72 65 2e 64 6c 6c } //50 Ransomware.dll
		$a_81_3 = {2e 74 65 73 74 } //10 .test
		$a_81_4 = {2e 44 41 52 58 49 53 } //10 .DARXIS
		$a_81_5 = {2e 44 63 52 61 74 } //10 .DcRat
		$a_81_6 = {45 6e 63 72 79 70 74 41 45 53 } //5 EncryptAES
		$a_81_7 = {5f 5f 4b 45 59 47 45 4e } //5 __KEYGEN
		$a_81_8 = {45 6e 63 72 79 70 74 65 64 20 46 69 6c 65 73 } //5 Encrypted Files
		$a_81_9 = {46 69 6c 65 45 6e 63 72 79 70 74 } //1 FileEncrypt
		$a_81_10 = {5f 5f 45 4e 43 52 59 50 54 49 4f 4e } //1 __ENCRYPTION
		$a_81_11 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //1 bytesToBeEncrypted
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*5+(#a_81_7  & 1)*5+(#a_81_8  & 1)*5+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=66
 
}