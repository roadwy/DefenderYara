
rule Ransom_Win32_DarkTrace_MA_MTB{
	meta:
		description = "Ransom:Win32/DarkTrace.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0b 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //3 vssadmin Delete Shadows /All /Quiet
		$a_01_1 = {59 6f 75 72 20 64 61 74 61 20 61 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //3 Your data are stolen and encrypted
		$a_01_2 = {54 68 65 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 70 75 62 6c 69 73 68 65 64 20 6f 6e 20 54 4f 52 20 77 65 62 73 69 74 65 20 69 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d 20 } //3 The data will be published on TOR website if you do not pay the ransom 
		$a_01_3 = {57 65 20 61 72 65 20 6e 6f 74 20 61 20 70 6f 6c 69 74 69 63 61 6c 6c 79 20 6d 6f 74 69 76 61 74 65 64 20 67 72 6f 75 70 20 61 6e 64 20 77 65 20 64 6f 20 6e 6f 74 20 6e 65 65 64 20 61 6e 79 74 68 69 6e 67 20 6f 74 68 65 72 20 74 68 61 6e 20 79 6f 75 72 20 6d 6f 6e 65 79 } //3 We are not a politically motivated group and we do not need anything other than your money
		$a_01_4 = {49 66 20 79 6f 75 20 70 61 79 2c 20 77 65 20 77 69 6c 6c 20 70 72 6f 76 69 64 65 20 79 6f 75 20 74 68 65 20 70 72 6f 67 72 61 6d 73 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 61 6e 64 20 77 65 20 77 69 6c 6c 20 64 65 6c 65 74 65 20 79 6f 75 72 20 64 61 74 61 } //3 If you pay, we will provide you the programs for decryption and we will delete your data
		$a_01_5 = {6b 69 6c 6c 5f 70 72 6f 63 65 73 73 65 73 } //3 kill_processes
		$a_01_6 = {64 65 6c 65 74 65 5f 65 76 65 6e 74 6c 6f 67 73 } //3 delete_eventlogs
		$a_01_7 = {4d 61 69 6c 20 28 4f 6e 69 6f 6e 4d 61 69 6c 29 20 53 75 70 70 6f 72 74 3a 20 64 61 72 6b 72 61 63 65 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //1 Mail (OnionMail) Support: darkrace@onionmail.org
		$a_01_8 = {44 61 72 6b 52 61 63 65 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 DarkRace ransomware
		$a_01_9 = {4c 6f 63 6b 42 69 74 20 33 2e 30 20 74 68 65 20 77 6f 72 6c 64 27 73 20 66 61 73 74 65 73 74 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 LockBit 3.0 the world's fastest ransomware
		$a_01_10 = {4d 61 69 6c 20 28 4f 6e 69 6f 6e 4d 61 69 6c 29 20 53 75 70 70 6f 72 74 3a 20 6c 6f 63 6b 64 61 72 6b 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //1 Mail (OnionMail) Support: lockdark@onionmail.org
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=23
 
}