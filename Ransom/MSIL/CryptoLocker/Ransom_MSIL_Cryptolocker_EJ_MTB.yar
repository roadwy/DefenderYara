
rule Ransom_MSIL_Cryptolocker_EJ_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0c 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //50 All of your files have been encrypted
		$a_81_1 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 63 72 79 70 74 65 64 } //50 Your personal files have been ecrypted
		$a_81_2 = {4e 6f 43 72 79 20 44 69 73 63 6f 72 64 } //50 NoCry Discord
		$a_81_3 = {72 65 61 64 5f 6d 65 20 66 6f 72 20 79 6f 75 72 20 66 69 6c 65 73 } //20 read_me for your files
		$a_81_4 = {68 69 64 64 65 6e 20 74 65 61 72 } //20 hidden tear
		$a_81_5 = {54 6d 39 44 63 6e 6b 71 } //20 Tm9Dcnkq
		$a_81_6 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //3 vssadmin delete shadows /all /quiet
		$a_81_7 = {45 6e 63 72 79 70 74 5f 52 6f 62 6f 74 } //3 Encrypt_Robot
		$a_81_8 = {4e 6f 43 72 79 2e 70 64 62 } //3 NoCry.pdb
		$a_81_9 = {45 6e 63 79 70 74 65 64 4b 65 79 } //1 EncyptedKey
		$a_81_10 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //1 bytesToBeEncrypted
		$a_81_11 = {5f 45 6e 63 72 79 70 74 65 64 24 } //1 _Encrypted$
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*20+(#a_81_4  & 1)*20+(#a_81_5  & 1)*20+(#a_81_6  & 1)*3+(#a_81_7  & 1)*3+(#a_81_8  & 1)*3+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=74
 
}