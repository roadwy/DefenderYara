
rule Ransom_MSIL_Cryptolocker_EH_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0c 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //50 Your files have been encrypted
		$a_81_1 = {52 61 6e 73 6f 6d 77 61 72 65 57 61 6e 6e 61 4d 61 64 } //50 RansomwareWannaMad
		$a_81_2 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //50 Your files are encrypted
		$a_81_3 = {4e 69 74 72 6f 20 52 61 6e 73 6f 6d 77 61 72 65 } //20 Nitro Ransomware
		$a_81_4 = {46 69 6c 65 73 20 44 65 63 72 79 70 74 65 64 } //20 Files Decrypted
		$a_81_5 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //20 vssadmin delete shadows /all /quiet
		$a_81_6 = {2e 67 69 76 65 6d 65 6e 69 74 72 6f } //3 .givemenitro
		$a_81_7 = {57 72 6f 6e 67 20 4b 65 79 20 62 61 68 61 68 61 } //3 Wrong Key bahaha
		$a_81_8 = {42 69 67 67 79 4c 6f 63 6b 65 72 } //3 BiggyLocker
		$a_81_9 = {4e 52 5f 64 65 63 72 79 70 74 } //1 NR_decrypt
		$a_81_10 = {45 6e 74 65 72 20 70 61 73 73 77 6f 72 64 } //1 Enter password
		$a_81_11 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 @protonmail.com
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*20+(#a_81_4  & 1)*20+(#a_81_5  & 1)*20+(#a_81_6  & 1)*3+(#a_81_7  & 1)*3+(#a_81_8  & 1)*3+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=74
 
}