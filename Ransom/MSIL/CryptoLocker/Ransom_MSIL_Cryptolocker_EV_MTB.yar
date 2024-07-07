
rule Ransom_MSIL_Cryptolocker_EV_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 06 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //50 All your files have been encrypted
		$a_81_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 20 62 79 20 61 20 52 61 6e 73 6f 6d 77 61 72 65 } //50 Your computer has been infected by a Ransomware
		$a_81_2 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //20 vssadmin delete shadows /all /quiet
		$a_81_3 = {40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d 20 } //3 @tutanota.com 
		$a_81_4 = {72 65 63 6f 76 65 72 79 73 63 6d 79 66 69 6c 65 73 } //3 recoveryscmyfiles
		$a_81_5 = {45 6e 63 72 79 70 74 65 64 4b 65 79 } //1 EncryptedKey
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*20+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*1) >=74
 
}