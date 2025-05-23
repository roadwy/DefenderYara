
rule Trojan_Win32_Qrob_RPP_MTB{
	meta:
		description = "Trojan:Win32/Qrob.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 63 6f 72 64 20 43 61 6e 61 72 79 } //1 Discord Canary
		$a_01_1 = {4f 70 65 72 61 20 47 58 } //1 Opera GX
		$a_01_2 = {53 70 75 74 6e 69 6b } //1 Sputnik
		$a_01_3 = {59 61 6e 64 65 78 42 72 6f 77 73 65 72 } //1 YandexBrowser
		$a_01_4 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
		$a_01_5 = {64 51 77 34 77 39 57 67 58 63 51 } //1 dQw4w9WgXcQ
		$a_01_6 = {62 36 34 64 65 63 6f 64 65 } //1 b64decode
		$a_01_7 = {67 65 74 69 70 28 29 } //1 getip()
		$a_01_8 = {54 6f 6b 65 6e 20 47 72 61 62 62 65 72 } //1 Token Grabber
		$a_01_9 = {41 73 74 72 61 61 } //1 Astraa
		$a_01_10 = {61 74 69 6f 2e 6a 70 67 } //1 atio.jpg
		$a_01_11 = {77 65 62 68 6f 6f 6b 73 } //1 webhooks
		$a_01_12 = {70 61 79 6c 6f 61 64 2e 65 6e 63 6f 64 65 28 29 } //1 payload.encode()
		$a_01_13 = {67 65 74 5f 74 6f 6b 65 6e 28 29 } //1 get_token()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=14
 
}