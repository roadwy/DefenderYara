
rule Ransom_Win64_Nova_MA_MTB{
	meta:
		description = "Ransom:Win64/Nova.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {2e 52 45 41 44 4d 45 2e 74 78 74 } //1 .README.txt
		$a_01_1 = {59 6f 75 72 20 75 6e 69 71 75 65 20 6e 65 74 77 6f 72 6b 20 49 64 3a 20 } //1 Your unique network Id: 
		$a_01_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 73 20 61 6e 64 20 73 65 72 76 65 72 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2c 20 62 61 63 6b 75 70 73 20 61 72 65 20 64 65 6c 65 74 65 64 } //1 Your computers and servers are encrypted, backups are deleted
		$a_01_3 = {57 65 20 75 73 65 20 73 74 72 6f 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e 20 61 6c 67 6f 72 69 74 68 6d 73 2c 20 73 6f 20 79 6f 75 20 63 61 6e 6e 6f 74 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 64 61 74 61 } //1 We use strong encryption algorithms, so you cannot decrypt your data
		$a_01_4 = {77 65 20 63 61 72 65 20 61 62 6f 75 74 20 6e 6f 74 68 69 6e 67 20 62 75 74 20 79 6f 75 72 20 6d 6f 6e 65 79 } //1 we care about nothing but your money
		$a_01_5 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 Do not rename encrypted files
		$a_01_6 = {3a 2f 2f 74 2e 6d 65 2f 4e 6f 76 61 47 72 6f 75 70 32 30 32 33 } //1 ://t.me/NovaGroup2023
		$a_01_7 = {65 6d 61 69 6c 20 61 74 20 6e 6f 76 61 67 72 6f 75 70 40 6f 6e 69 6f 6e 6d 61 69 6c } //1 email at novagroup@onionmail
		$a_01_8 = {72 61 6e 73 6f 6d 77 61 72 65 20 69 73 20 61 20 70 61 72 74 20 6f 66 20 74 68 65 20 77 6f 72 6c 64 20 6f 66 20 63 79 62 65 72 20 73 65 63 75 72 69 74 79 } //1 ransomware is a part of the world of cyber security
		$a_01_9 = {79 6f 75 20 67 6f 74 20 68 61 63 6b 65 64 } //1 you got hacked
		$a_01_10 = {54 68 65 20 76 69 72 75 73 20 68 61 73 20 74 68 65 20 61 62 69 6c 69 74 79 20 74 6f 20 73 65 6c 66 2d 64 65 73 74 72 75 63 74 } //1 The virus has the ability to self-destruct
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}