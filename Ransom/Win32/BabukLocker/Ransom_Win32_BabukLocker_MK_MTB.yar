
rule Ransom_Win32_BabukLocker_MK_MTB{
	meta:
		description = "Ransom:Win32/BabukLocker.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin.exe delete shadows /all /quiet
		$a_81_1 = {42 41 42 55 4b 20 4c 4f 43 4b 45 52 } //1 BABUK LOCKER
		$a_81_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 73 20 61 6e 64 20 73 65 72 76 65 72 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Your computers and servers are encrypted
		$a_81_3 = {21 21 21 20 44 41 4e 47 45 52 20 21 21 21 } //1 !!! DANGER !!!
		$a_81_4 = {48 6f 77 20 54 6f 20 52 65 73 74 6f 72 65 20 59 6f 75 72 20 46 69 6c 65 73 2e 74 78 74 } //1 How To Restore Your Files.txt
		$a_81_5 = {65 63 64 68 5f 70 75 62 5f 6b 2e 62 69 6e } //1 ecdh_pub_k.bin
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}
rule Ransom_Win32_BabukLocker_MK_MTB_2{
	meta:
		description = "Ransom:Win32/BabukLocker.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2f 00 2f 00 08 00 00 "
		
	strings :
		$a_81_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //10 vssadmin.exe delete shadows /all /quiet
		$a_81_1 = {72 61 6e 73 6f 6d 77 61 72 65 } //5 ransomware
		$a_81_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 73 20 61 6e 64 20 73 65 72 76 65 72 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //10 Your computers and servers are encrypted
		$a_81_3 = {6e 6f 62 6f 64 79 20 77 69 6c 6c 20 70 61 79 20 75 73 } //10 nobody will pay us
		$a_02_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 61 00 62 00 75 00 6b 00 90 02 10 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00 6c 00 6f 00 67 00 69 00 6e 00 2e 00 70 00 68 00 70 00 3f 00 69 00 64 00 3d 00 90 00 } //1
		$a_02_5 = {68 74 74 70 3a 2f 2f 62 61 62 75 6b 90 02 10 2e 6f 6e 69 6f 6e 2f 6c 6f 67 69 6e 2e 70 68 70 3f 69 64 3d 90 00 } //1
		$a_81_6 = {2e 62 61 62 79 6b } //1 .babyk
		$a_81_7 = {48 6f 77 20 54 6f 20 52 65 73 74 6f 72 65 20 59 6f 75 72 20 46 69 6c 65 73 2e 74 78 74 } //10 How To Restore Your Files.txt
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*5+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*10) >=47
 
}