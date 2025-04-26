
rule Ransom_MSIL_Cryptolocker_EG_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0c 00 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 73 20 65 6e 63 72 79 70 74 65 64 20 73 65 63 75 72 65 6c 79 } //50 files encrypted securely
		$a_81_1 = {43 68 61 6f 73 20 52 61 6e 73 6f 6d 77 61 72 65 } //50 Chaos Ransomware
		$a_81_2 = {41 6c 6c 20 59 6f 75 72 20 49 6d 70 6f 72 74 61 6e 74 20 46 69 6c 65 73 20 41 72 65 20 45 6e 63 72 79 70 74 65 64 } //50 All Your Important Files Are Encrypted
		$a_81_3 = {45 6e 63 72 79 70 74 65 64 20 46 69 6c 65 73 } //20 Encrypted Files
		$a_81_4 = {62 79 74 65 73 54 6f 42 65 44 65 63 72 79 70 74 65 64 } //20 bytesToBeDecrypted
		$a_81_5 = {48 6f 77 20 74 6f 20 52 65 63 6f 76 65 72 20 4d 79 20 46 69 6c 65 73 } //20 How to Recover My Files
		$a_81_6 = {2e 66 69 72 65 63 72 79 70 74 } //3 .firecrypt
		$a_81_7 = {2e 63 68 61 6f 73 } //3 .chaos
		$a_81_8 = {2e 44 61 72 6b 43 72 79 } //3 .DarkCry
		$a_81_9 = {40 73 69 67 61 69 6e 74 2e 6f 72 67 } //1 @sigaint.org
		$a_81_10 = {41 45 53 5f 44 65 63 72 79 70 74 } //1 AES_Decrypt
		$a_81_11 = {4e 6f 43 72 79 } //1 NoCry
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*20+(#a_81_4  & 1)*20+(#a_81_5  & 1)*20+(#a_81_6  & 1)*3+(#a_81_7  & 1)*3+(#a_81_8  & 1)*3+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=74
 
}