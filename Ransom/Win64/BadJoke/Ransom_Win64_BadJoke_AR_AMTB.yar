
rule Ransom_Win64_BadJoke_AR_AMTB{
	meta:
		description = "Ransom:Win64/BadJoke.AR!AMTB,SIGNATURE_TYPE_PEHSTR,07 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {5b 2b 5d 20 49 6e 73 74 61 6c 6c 69 6e 67 20 62 61 63 6b 64 6f 6f 72 2e 2e 2e } //1 [+] Installing backdoor...
		$a_01_1 = {5b 2b 5d 20 52 61 6e 73 6f 6d 77 61 72 65 20 64 65 70 6c 6f 79 69 6e 67 2e 2e 2e } //1 [+] Ransomware deploying...
		$a_01_2 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //1 YOUR FILES HAVE BEEN ENCRYPTED
		$a_01_3 = {44 45 50 4c 4f 59 49 4e 47 20 52 41 4e 53 4f 4d 57 41 52 45 20 50 41 59 4c 4f 41 44 } //1 DEPLOYING RANSOMWARE PAYLOAD
		$a_01_4 = {49 4e 49 54 49 41 54 49 4e 47 20 44 41 54 41 20 44 45 53 54 52 55 43 54 49 4f 4e 20 53 45 51 55 45 4e 43 45 } //1 INITIATING DATA DESTRUCTION SEQUENCE
		$a_01_5 = {42 69 74 63 6f 69 6e 20 61 64 64 72 65 73 73 20 66 6f 72 20 70 61 79 6d 65 6e 74 3a 20 31 42 76 42 4d 53 45 59 73 74 57 65 74 71 54 46 6e 35 41 75 34 6d 34 47 46 67 37 78 4a 61 4e 56 4e 32 } //1 Bitcoin address for payment: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
		$a_01_6 = {48 61 63 6b 69 6e 67 20 47 72 6f 75 70 20 22 53 68 61 64 6f 77 20 53 79 6e 64 69 63 61 74 65 22 } //1 Hacking Group "Shadow Syndicate"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}