
rule Ransom_MSIL_Cryptolocker_EM_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0c 00 00 "
		
	strings :
		$a_81_0 = {57 68 61 74 20 63 61 6e 20 49 20 64 6f 20 74 6f 20 67 65 74 20 6d 79 20 66 69 6c 65 73 20 62 61 63 6b } //50 What can I do to get my files back
		$a_81_1 = {59 6f 75 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //50 You personal files are encrypted
		$a_81_2 = {59 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 76 69 64 65 6f 73 2c 20 6d 75 73 69 63 2c 20 69 6d 61 67 65 73 2c 20 64 6f 63 75 6d 65 6e 74 73 20 2e 2e 2e 20 65 74 63 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 65 6e 63 72 79 70 74 69 6f 6e } //50 Your important files videos, music, images, documents ... etc are encrypted with encryption
		$a_81_3 = {44 45 43 52 59 50 54 59 4f 55 52 46 49 4c 45 53 } //20 DECRYPTYOURFILES
		$a_81_4 = {40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //20 @protonmail.com
		$a_81_5 = {62 69 74 63 6f 69 6e 20 61 64 64 72 65 73 73 } //20 bitcoin address
		$a_81_6 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //3 vssadmin delete shadows /all /quiet
		$a_81_7 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //3 DisableTaskMgr
		$a_81_8 = {2e 66 75 63 6b 69 6e 67 } //3 .fucking
		$a_81_9 = {42 69 74 63 6f 69 6e 20 41 64 64 72 65 73 73 3a } //1 Bitcoin Address:
		$a_81_10 = {57 6e 43 72 79 } //1 WnCry
		$a_81_11 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //1 ransom.jpg
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*20+(#a_81_4  & 1)*20+(#a_81_5  & 1)*20+(#a_81_6  & 1)*3+(#a_81_7  & 1)*3+(#a_81_8  & 1)*3+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=74
 
}