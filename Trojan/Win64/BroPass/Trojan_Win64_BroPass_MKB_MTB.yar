
rule Trojan_Win64_BroPass_MKB_MTB{
	meta:
		description = "Trojan:Win64/BroPass.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4b 00 4b 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6c 69 6e 67 20 57 69 46 69 20 70 61 73 73 77 6f 72 64 73 } //15 Stealing WiFi passwords
		$a_01_1 = {53 74 65 61 6c 69 6e 67 20 54 65 6c 65 67 72 61 6d 20 73 65 73 73 69 6f 6e } //15 Stealing Telegram session
		$a_01_2 = {43 68 65 63 6b 69 6e 67 20 66 6f 72 20 63 72 79 70 74 6f 20 77 61 6c 6c 65 74 73 } //15 Checking for crypto wallets
		$a_01_3 = {53 74 65 61 6c 69 6e 67 20 57 68 61 74 73 41 70 70 20 73 65 73 73 69 6f 6e 73 20 28 42 72 6f 77 73 65 72 20 2b 20 53 74 6f 72 65 20 2b 20 44 65 73 6b 74 6f 70 29 } //10 Stealing WhatsApp sessions (Browser + Store + Desktop)
		$a_01_4 = {45 78 74 72 61 63 74 69 6e 67 20 62 72 6f 77 73 65 72 20 61 75 74 6f 66 69 6c 6c 73 } //10 Extracting browser autofills
		$a_01_5 = {53 74 65 61 6c 69 6e 67 20 56 50 4e 20 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 73 } //5 Stealing VPN configurations
		$a_01_6 = {53 74 65 61 6c 69 6e 67 20 63 6c 69 70 62 6f 61 72 64 20 64 61 74 61 } //5 Stealing clipboard data
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*15+(#a_01_2  & 1)*15+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=75
 
}