
rule Ransom_Win64_LockBit_GVA_MTB{
	meta:
		description = "Ransom:Win64/LockBit.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0a 00 00 "
		
	strings :
		$a_01_0 = {2e 78 6c 6f 63 6b } //1 .xlock
		$a_01_1 = {4c 6f 63 6b 42 69 74 20 33 2e 30 20 74 68 65 20 77 6f 72 6c 64 27 73 20 66 61 73 74 65 73 74 20 72 61 6e 73 6f 6d 77 61 72 65 20 73 69 6e 63 65 20 32 30 31 39 } //3 LockBit 3.0 the world's fastest ransomware since 2019
		$a_01_2 = {59 6f 75 72 20 64 61 74 61 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 Your data are stolen and encrypted
		$a_01_3 = {54 68 65 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 70 75 62 6c 69 73 68 65 64 20 6f 6e 20 54 4f 52 20 77 65 62 73 69 74 65 20 69 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d 20 } //1 The data will be published on TOR website if you do not pay the ransom 
		$a_01_4 = {59 6f 75 20 6e 65 65 64 20 63 6f 6e 74 61 63 74 20 75 73 20 61 6e 64 20 64 65 63 72 79 70 74 20 6f 6e 65 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 } //1 You need contact us and decrypt one file for free
		$a_01_5 = {59 6f 75 20 63 61 6e 20 63 6f 6e 74 61 63 74 20 75 73 20 69 6e 20 65 6d 61 69 6c 20 6f 72 20 71 74 6f 78 2e } //1 You can contact us in email or qtox.
		$a_01_6 = {57 61 72 6e 69 6e 67 21 20 44 6f 20 6e 6f 74 20 44 45 4c 45 54 45 20 6f 72 20 4d 4f 44 49 46 59 20 61 6e 79 20 66 69 6c 65 73 2c 20 69 74 20 63 61 6e 20 6c 65 61 64 20 74 6f 20 72 65 63 6f 76 65 72 79 20 70 72 6f 62 6c 65 6d 73 21 } //1 Warning! Do not DELETE or MODIFY any files, it can lead to recovery problems!
		$a_01_7 = {57 6f 75 6c 64 20 79 6f 75 20 6c 69 6b 65 20 74 6f 20 65 61 72 6e 20 6d 69 6c 6c 69 6f 6e 73 20 6f 66 20 64 6f 6c 6c 61 72 73 20 24 24 24 20 3f } //1 Would you like to earn millions of dollars $$$ ?
		$a_01_8 = {6d 61 69 6e 2e 74 72 61 76 65 72 73 65 41 6e 64 45 6e 63 72 79 70 74 44 69 73 6b } //1 main.traverseAndEncryptDisk
		$a_01_9 = {6d 61 69 6e 2e 6c 6f 61 64 52 53 41 50 75 62 6c 69 63 4b 65 79 46 72 6f 6d 50 45 4d } //1 main.loadRSAPublicKeyFromPEM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=12
 
}