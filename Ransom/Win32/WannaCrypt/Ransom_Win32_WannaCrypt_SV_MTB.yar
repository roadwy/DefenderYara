
rule Ransom_Win32_WannaCrypt_SV_MTB{
	meta:
		description = "Ransom:Win32/WannaCrypt.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 61 6e 6e 61 4c 6f 63 6b 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 WannaLock Ransomware
		$a_01_1 = {59 4f 55 52 20 50 43 20 48 41 53 20 42 45 45 4e 20 4c 4f 43 4b 45 44 20 42 59 20 57 41 4e 4e 41 4c 4f 43 4b 20 52 41 4e 53 4f 4d 57 41 52 45 21 21 21 } //1 YOUR PC HAS BEEN LOCKED BY WANNALOCK RANSOMWARE!!!
		$a_01_2 = {50 4c 45 41 53 45 20 43 4f 4e 54 41 43 54 20 68 74 74 70 73 3a 2f 2f 6d 65 73 73 61 67 65 2e 62 69 6c 69 62 69 6c 69 2e 63 6f 6d 2f 23 77 68 69 73 70 65 72 2f 6d 69 64 34 39 30 38 32 35 32 38 30 20 54 4f 20 46 49 58 20 59 4f 55 52 20 50 43 21 21 21 } //1 PLEASE CONTACT https://message.bilibili.com/#whisper/mid490825280 TO FIX YOUR PC!!!
		$a_01_3 = {59 4f 55 20 4d 55 53 54 20 43 4f 4d 50 4c 45 54 45 20 54 48 49 53 20 49 4e 20 4f 4e 45 20 48 4f 55 52 21 21 21 4f 52 20 59 4f 55 20 4d 55 53 54 20 53 41 59 20 42 59 45 20 42 59 45 20 54 4f 20 59 4f 55 52 20 50 43 21 21 21 } //1 YOU MUST COMPLETE THIS IN ONE HOUR!!!OR YOU MUST SAY BYE BYE TO YOUR PC!!!
		$a_01_4 = {44 4f 4e 54 20 52 45 42 4f 4f 54 20 59 4f 55 52 20 50 43 20 42 45 43 41 55 53 45 20 54 48 49 53 20 57 49 4c 4c 20 4b 49 4c 4c 20 59 4f 55 52 20 50 43 21 21 21 } //1 DONT REBOOT YOUR PC BECAUSE THIS WILL KILL YOUR PC!!!
		$a_01_5 = {59 6f 75 72 20 50 65 6e 73 6f 6e 61 6c 20 4e 75 6d 62 65 72 3a } //1 Your Pensonal Number:
		$a_01_6 = {65 6e 74 65 72 20 6b 65 79 20 62 65 6c 6f 77 3a } //1 enter key below:
		$a_01_7 = {52 49 47 48 54 20 4b 45 59 21 21 21 44 45 43 52 59 50 54 49 4e 47 21 21 21 } //1 RIGHT KEY!!!DECRYPTING!!!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}