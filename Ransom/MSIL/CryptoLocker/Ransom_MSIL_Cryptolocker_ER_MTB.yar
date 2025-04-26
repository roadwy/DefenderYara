
rule Ransom_MSIL_Cryptolocker_ER_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 08 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 6c 69 6b 65 20 70 69 63 74 75 72 65 73 2c 20 64 61 74 61 62 61 73 65 73 2c 20 64 6f 63 75 6d 65 6e 74 73 2c 61 70 6c 69 63 61 74 69 6f 6e 73 20 61 6e 64 20 6f 74 68 65 72 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //50 All your files like pictures, databases, documents,aplications and other are encrypted
		$a_81_1 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 61 72 65 20 62 65 69 6e 67 20 64 65 6c 65 74 65 64 } //50 Your personal files are being deleted
		$a_81_2 = {2e 64 65 6c 74 61 70 61 79 6d 65 6e 74 62 69 74 63 6f 69 6e } //20 .deltapaymentbitcoin
		$a_81_3 = {46 69 6c 65 54 6f 45 6e 63 72 79 70 74 } //20 FileToEncrypt
		$a_81_4 = {4e 6f 70 79 66 79 5f 52 61 6e 73 6f 6d 77 61 72 65 } //3 Nopyfy_Ransomware
		$a_81_5 = {4a 69 67 73 61 77 } //3 Jigsaw
		$a_81_6 = {59 6f 75 20 41 72 65 20 48 61 63 6b 65 64 } //1 You Are Hacked
		$a_81_7 = {45 6e 63 72 79 70 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 } //1 Encryption Complete
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=74
 
}