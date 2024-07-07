
rule Ransom_MSIL_Cryptolocker_EC_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 08 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 28 63 6f 75 6e 74 3a 20 6e 29 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //50 Your files (count: n) are encrypted
		$a_81_1 = {52 61 73 6f 6d 77 61 72 65 32 2e 5f 30 } //50 Rasomware2._0
		$a_81_2 = {66 72 69 65 6e 64 6c 79 2e 63 79 62 65 72 2e 63 72 69 6d 69 6e 61 6c } //20 friendly.cyber.criminal
		$a_81_3 = {70 72 6f 6a 65 63 74 35 37 37 } //20 project577
		$a_81_4 = {52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 } //3 RECOVER__FILES
		$a_81_5 = {41 45 53 5f 45 6e 63 72 79 70 74 } //3 AES_Encrypt
		$a_81_6 = {2e 41 45 53 36 34 } //1 .AES64
		$a_81_7 = {46 72 65 65 7a 65 4d 6f 75 73 65 } //1 FreezeMouse
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=74
 
}