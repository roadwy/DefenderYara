
rule Trojan_BAT_BlitzedGrabber_CXLM_MTB{
	meta:
		description = "Trojan:BAT/BlitzedGrabber.CXLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 14 00 00 "
		
	strings :
		$a_01_0 = {2a 00 2a 00 42 00 4c 00 49 00 54 00 5a 00 45 00 44 00 20 00 47 00 52 00 41 00 42 00 42 00 45 00 52 00 } //1 **BLITZED GRABBER
		$a_01_1 = {4d 00 61 00 69 00 6e 00 20 00 53 00 74 00 65 00 61 00 6c 00 69 00 6e 00 67 00 } //1 Main Stealing
		$a_01_2 = {54 00 6f 00 6b 00 65 00 6e 00 73 00 2e 00 74 00 78 00 74 00 } //1 Tokens.txt
		$a_01_3 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 } //1 Passwords
		$a_01_4 = {43 00 72 00 65 00 64 00 69 00 74 00 20 00 43 00 61 00 72 00 64 00 73 00 } //1 Credit Cards
		$a_01_5 = {57 00 49 00 46 00 49 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 WIFI Password
		$a_01_6 = {47 00 61 00 6d 00 69 00 6e 00 67 00 20 00 41 00 63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 } //1 Gaming Accounts
		$a_01_7 = {4d 00 69 00 6e 00 65 00 63 00 72 00 61 00 66 00 74 00 } //1 Minecraft
		$a_01_8 = {53 00 74 00 65 00 61 00 6d 00 } //1 Steam
		$a_01_9 = {62 00 69 00 74 00 63 00 6f 00 69 00 6e 00 } //1 bitcoin
		$a_01_10 = {6d 00 6f 00 6e 00 65 00 72 00 6f 00 } //1 monero
		$a_01_11 = {65 00 74 00 68 00 65 00 72 00 69 00 75 00 6d 00 } //1 etherium
		$a_01_12 = {73 00 74 00 65 00 6c 00 6c 00 61 00 72 00 63 00 6f 00 69 00 6e 00 } //1 stellarcoin
		$a_01_13 = {62 00 6c 00 6f 00 63 00 6b 00 63 00 68 00 61 00 69 00 6e 00 } //1 blockchain
		$a_01_14 = {41 00 6d 00 65 00 78 00 20 00 43 00 61 00 72 00 64 00 } //1 Amex Card
		$a_01_15 = {42 00 43 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 } //1 BCGlobal
		$a_01_16 = {44 00 69 00 6e 00 65 00 72 00 73 00 20 00 43 00 6c 00 75 00 62 00 20 00 43 00 61 00 72 00 64 00 } //1 Diners Club Card
		$a_01_17 = {5c 00 4f 00 70 00 65 00 72 00 61 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 70 00 65 00 72 00 61 00 20 00 53 00 74 00 61 00 62 00 6c 00 65 00 } //1 \Opera Software\Opera Stable
		$a_01_18 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 } //1 \Google\Chrome\User Data\Default
		$a_01_19 = {5c 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 5c 00 6c 00 65 00 76 00 65 00 6c 00 64 00 62 00 } //1 \Local Storage\leveldb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1) >=20
 
}