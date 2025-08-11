
rule Ransom_MSIL_CyberLock_GVA_MTB{
	meta:
		description = "Ransom:MSIL/CyberLock.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 "
		
	strings :
		$a_01_0 = {2e 63 79 62 65 72 6c 6f 63 6b } //1 .cyberlock
		$a_01_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //1 All your files have been encrypted.
		$a_01_2 = {48 6f 77 20 64 6f 20 49 20 70 61 79 3f } //1 How do I pay?
		$a_01_3 = {59 6f 75 20 6d 75 73 74 20 73 65 6e 64 20 24 20 32 35 30 30 30 20 28 55 53 44 29 20 74 6f 20 74 68 65 20 66 69 72 73 74 20 4d 6f 6e 65 72 6f 20 61 64 64 72 65 73 73 } //1 You must send $ 25000 (USD) to the first Monero address
		$a_01_4 = {57 65 20 61 72 65 20 43 79 62 65 72 4c 6f 63 6b 20 2d 20 41 6e 6f 6e 79 6d 6f 75 73 2e } //1 We are CyberLock - Anonymous.
		$a_01_5 = {52 65 61 64 4d 65 4e 6f 77 2e 74 78 74 } //1 ReadMeNow.txt
		$a_01_6 = {48 4b 43 55 3a 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 } //1 HKCU:\Control Panel\Desktop
		$a_01_7 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 63 69 70 68 65 72 2e 65 78 65 20 2d 41 72 67 75 6d 65 6e 74 4c 69 73 74 20 22 2f 77 3a 24 65 6e 76 3a 55 53 45 52 50 52 4f 46 49 4c 45 22 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e } //1 Start-Process cipher.exe -ArgumentList "/w:$env:USERPROFILE" -WindowStyle Hidden
		$a_01_8 = {45 6d 61 69 6c 3a 20 63 79 62 65 72 73 70 65 63 74 72 65 69 73 6c 6f 63 6b 65 64 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //5 Email: cyberspectreislocked@onionmail.org
		$a_01_9 = {50 6c 65 61 73 65 20 73 65 6e 64 20 61 20 73 63 72 65 65 6e 73 68 6f 74 20 6f 66 20 74 68 65 20 70 61 79 6d 65 6e 74 2e 20 57 65 20 77 69 6c 6c 20 72 65 73 70 6f 6e 64 20 77 69 74 68 69 6e 20 35 20 68 6f 75 72 73 20 77 69 74 68 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 2e } //1 Please send a screenshot of the payment. We will respond within 5 hours with the decryption key.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*5+(#a_01_9  & 1)*1) >=14
 
}