
rule Ransom_Win64_FileCrypter_NC_MTB{
	meta:
		description = "Ransom:Win64/FileCrypter.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0a 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 63 65 20 74 68 65 20 6d 6f 6e 65 79 20 68 61 76 65 20 62 65 65 6e 20 72 65 63 69 65 76 65 64 2c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 61 75 74 6f 6d 61 74 69 63 61 6c 6c 79 20 64 65 63 72 79 70 74 65 64 } //2 Once the money have been recieved, your files will be automatically decrypted
		$a_01_1 = {59 4f 55 52 20 53 59 53 54 45 4d 20 49 53 20 43 4f 4d 50 52 4f 4d 49 53 45 44 21 20 52 45 41 44 20 54 48 49 53 20 4d 45 53 53 41 47 45 20 43 41 52 45 46 55 4c 4c 59 21 } //2 YOUR SYSTEM IS COMPROMISED! READ THIS MESSAGE CAREFULLY!
		$a_01_2 = {61 6e 64 20 61 6c 6c 20 79 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 68 69 6a 61 63 6b 65 64 2e 20 4d 65 61 6e 69 6e 67 20 77 65 20 68 61 76 65 20 61 63 63 65 73 73 20 74 6f 20 41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 } //1 and all your system has been hijacked. Meaning we have access to ALL YOUR FILES
		$a_01_3 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2c } //1 All your files have been encrypted,
		$a_01_4 = {66 6f 72 20 61 6e 79 6f 6e 65 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 2e 20 54 68 69 73 20 69 6e 63 6c 75 64 65 73 20 79 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 64 61 74 61 2c 20 70 61 73 73 77 6f 72 64 73 2c 20 61 6e 64 20 6d 6f 72 65 } //1 for anyone to download. This includes your personal data, passwords, and more
		$a_01_5 = {59 4f 55 20 41 52 45 20 52 45 53 50 4f 4e 53 49 42 4c 45 20 46 4f 52 20 50 41 59 49 4e 47 20 54 48 45 20 4d 4f 4e 45 59 2c 20 49 46 20 59 4f 55 20 4d 45 53 53 20 49 54 20 55 50 20 49 54 20 49 53 20 59 4f 55 52 20 46 41 55 4c 54 } //1 YOU ARE RESPONSIBLE FOR PAYING THE MONEY, IF YOU MESS IT UP IT IS YOUR FAULT
		$a_01_6 = {61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 70 75 62 6c 69 63 20 6f 6e 20 74 68 65 20 69 6e 74 65 72 6e 65 74 } //1 all your files will be public on the internet
		$a_01_7 = {53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 20 24 74 72 75 65 } //1 Set-MpPreference -DisableRealtimeMonitoring $true
		$a_01_8 = {53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 44 69 73 61 62 6c 65 43 6c 6f 75 64 50 72 6f 74 65 63 74 69 6f 6e 20 24 74 72 75 65 } //1 Set-MpPreference -DisableCloudProtection $true
		$a_01_9 = {72 61 6e 73 6f 6d 77 61 72 65 } //1 ransomware
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=12
 
}