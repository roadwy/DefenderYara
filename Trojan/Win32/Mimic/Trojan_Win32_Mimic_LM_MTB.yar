
rule Trojan_Win32_Mimic_LM_MTB{
	meta:
		description = "Trojan:Win32/Mimic.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffab 00 ffffffab 00 12 00 00 "
		
	strings :
		$a_81_0 = {44 65 63 72 79 70 74 20 74 6f 6f 6c } //1 Decrypt tool
		$a_81_1 = {4d 49 4d 49 43 5f 4c 4f 47 2e 74 78 74 } //2 MIMIC_LOG.txt
		$a_81_2 = {4d 49 4d 49 43 5f 44 45 43 52 59 50 54 2e 74 78 74 } //3 MIMIC_DECRYPT.txt
		$a_81_3 = {59 6f 75 72 42 75 6e 6e 79 57 72 6f 74 65 } //4 YourBunnyWrote
		$a_81_4 = {43 4c 4f 4e 45 20 49 4e 46 4f 3a 20 49 27 6d 20 61 20 63 6c 6f 6e 65 21 } //5 CLONE INFO: I'm a clone!
		$a_81_5 = {43 4c 4f 4e 45 20 49 4e 46 4f 3a 20 49 27 6d 20 6f 72 69 67 69 6e 61 6c 20 70 72 6f 63 65 73 73 21 } //6 CLONE INFO: I'm original process!
		$a_81_6 = {54 68 69 73 20 66 69 6c 65 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 6e 6f 74 68 65 72 20 6b 65 79 20 6f 72 20 6e 6f 74 20 65 6e 63 72 79 70 74 65 64 20 65 76 65 72 } //7 This file was encrypted with another key or not encrypted ever
		$a_81_7 = {43 61 6e 6e 6f 74 20 64 65 63 72 79 70 74 20 66 69 6c 65 20 61 66 74 65 72 20 65 6e 63 72 79 70 74 6f 72 20 76 65 72 73 69 6f 6e } //8 Cannot decrypt file after encryptor version
		$a_81_8 = {44 65 63 72 79 70 74 69 6f 6e 20 66 69 6e 69 73 68 65 64 2e } //9 Decryption finished.
		$a_81_9 = {53 79 73 74 65 6d 20 73 68 6f 75 6c 64 20 62 65 20 72 65 62 6f 6f 74 65 64 20 69 6e 20 33 30 20 73 65 63 6f 6e 64 73 2e 2e 2e } //10 System should be rebooted in 30 seconds...
		$a_81_10 = {53 65 63 72 65 74 20 6b 65 79 20 66 6f 75 6e 64 3a } //11 Secret key found:
		$a_81_11 = {68 61 73 68 6c 69 73 74 2e 74 78 74 } //12 hashlist.txt
		$a_81_12 = {6d 64 35 5f 63 68 65 63 6b 2e 74 78 74 } //13 md5_check.txt
		$a_81_13 = {52 65 6d 6f 76 65 20 64 65 62 75 67 67 65 72 2e 2e 2e } //14 Remove debugger...
		$a_81_14 = {4b 69 6c 6c 20 43 72 79 70 74 6f 72 2e 2e 2e } //15 Kill Cryptor...
		$a_81_15 = {44 65 6c 65 74 65 20 73 65 73 73 69 6f 6e 20 6b 65 79 2e 2e 2e } //16 Delete session key...
		$a_81_16 = {52 65 73 74 6f 72 65 20 53 65 72 76 69 63 65 73 2e 2e 2e } //17 Restore Services...
		$a_81_17 = {52 65 73 74 6f 72 65 20 50 72 6f 63 65 73 73 65 73 2e 2e 2e } //18 Restore Processes...
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6+(#a_81_6  & 1)*7+(#a_81_7  & 1)*8+(#a_81_8  & 1)*9+(#a_81_9  & 1)*10+(#a_81_10  & 1)*11+(#a_81_11  & 1)*12+(#a_81_12  & 1)*13+(#a_81_13  & 1)*14+(#a_81_14  & 1)*15+(#a_81_15  & 1)*16+(#a_81_16  & 1)*17+(#a_81_17  & 1)*18) >=171
 
}