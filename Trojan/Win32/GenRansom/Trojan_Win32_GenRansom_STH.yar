
rule Trojan_Win32_GenRansom_STH{
	meta:
		description = "Trojan:Win32/GenRansom.STH,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0f 00 00 "
		
	strings :
		$a_80_0 = {41 6c 6c 20 46 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 78 66 69 6c 74 72 61 74 65 64 } //All Files has been exfiltrated  1
		$a_80_1 = {41 63 63 65 73 73 20 64 65 6e 69 65 64 20 74 6f 20 66 69 6c 65 } //Access denied to file  1
		$a_80_2 = {49 4d 50 4f 52 54 41 4e 54 3a 20 4b 65 65 70 20 74 68 69 73 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 73 61 66 65 20 61 6e 64 20 73 65 63 75 72 65 2e 20 57 69 74 68 6f 75 74 20 69 74 2c 20 79 6f 75 20 63 61 6e 6e 6f 74 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2e } //IMPORTANT: Keep this information safe and secure. Without it, you cannot decrypt your files.  1
		$a_80_3 = {45 6e 63 72 79 70 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 2e } //Encryption complete.  1
		$a_80_4 = {53 74 61 72 74 69 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e 20 6f 6e } //Starting encryption on  1
		$a_80_5 = {4c 4f 43 4b 42 49 54 5f 53 49 47 4e 41 54 55 52 45 } //LOCKBIT_SIGNATURE  1
		$a_80_6 = {54 72 61 6e 73 66 65 72 46 69 6c 65 73 56 69 61 46 54 50 } //TransferFilesViaFTP  1
		$a_80_7 = {41 45 53 5f 42 4c 4f 43 4b 5f 53 49 5a 45 } //AES_BLOCK_SIZE  1
		$a_80_8 = {4b 45 59 5f 53 49 5a 45 } //KEY_SIZE  1
		$a_80_9 = {46 54 50 20 54 72 61 6e 73 66 65 72 20 45 72 72 6f 72 3a } //FTP Transfer Error:  1
		$a_80_10 = {53 54 4f 52 } //STOR  1
		$a_80_11 = {66 74 70 3a 2f 2f } //ftp://  1
		$a_80_12 = {46 74 70 57 65 62 52 65 71 75 65 73 74 } //FtpWebRequest  1
		$a_80_13 = {65 6e 63 72 79 70 74 69 6f 6e 5f 6d 65 73 73 61 67 65 2e 74 78 74 } //encryption_message.txt  2
		$a_80_14 = {65 6d 61 69 6c 3a 20 68 61 63 6b 65 72 73 5f 6c 6f 63 6b 52 61 6e 73 6f 6d 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //email: hackers_lockRansom@protonmail.com  5
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*2+(#a_80_14  & 1)*5) >=7
 
}