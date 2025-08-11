
rule Ransom_Win64_LockBit_AQUA_MTB{
	meta:
		description = "Ransom:Win64/LockBit.AQUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 09 00 00 "
		
	strings :
		$a_81_0 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----BEGIN RSA PUBLIC KEY-----
		$a_81_1 = {2d 2d 2d 2d 2d 45 4e 44 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----END RSA PUBLIC KEY-----
		$a_81_2 = {5c 77 6f 72 6b 5c 74 6f 6f 6c 73 5c 61 69 5c 61 6b 34 37 5c 63 70 70 5c 65 6e 63 72 79 70 74 5c 65 6e 63 72 79 70 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 65 6e 63 72 79 70 74 2e 70 64 62 } //3 \work\tools\ai\ak47\cpp\encrypt\encrypt\x64\Release\encrypt.pdb
		$a_81_3 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //1 GetLogicalDrives
		$a_81_4 = {48 6f 77 20 74 6f 20 64 65 63 72 79 70 74 20 6d 79 20 64 61 74 61 2e 74 78 74 } //1 How to decrypt my data.txt
		$a_81_5 = {64 65 63 72 79 70 74 69 6f 6e 64 65 73 63 72 69 70 74 69 6f 6e 2e 70 64 66 } //1 decryptiondescription.pdf
		$a_81_6 = {49 6d 70 6f 72 74 61 6e 74 21 21 21 2e 70 64 66 } //3 Important!!!.pdf
		$a_81_7 = {2e 6c 6f 63 6b } //1 .lock
		$a_81_8 = {48 6f 77 20 74 6f 20 64 65 63 72 79 70 74 20 6d 79 20 64 61 74 61 2e 6c 6f 67 } //1 How to decrypt my data.log
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*3+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*3+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=13
 
}