
rule Trojan_Win32_PasswordStealer_KA_MTB{
	meta:
		description = "Trojan:Win32/PasswordStealer.KA!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {6d 6e 70 61 79 6d 65 6e 74 73 } //1 mnpayments
		$a_01_1 = {5c 66 69 6c 65 73 5c 57 61 6c 6c 65 74 73 } //1 \files\Wallets
		$a_01_2 = {6d 75 6c 74 69 64 6f 67 65 2e 77 61 6c 6c 65 74 } //1 multidoge.wallet
		$a_01_3 = {5c 45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 } //1 \Exodus\exodus.wallet
		$a_01_4 = {6b 65 79 73 74 6f 72 65 } //1 keystore
		$a_01_5 = {53 45 4c 45 43 54 20 61 63 74 69 6f 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //1 SELECT action_url, username_value, password_value FROM logins
		$a_01_6 = {66 69 6c 65 73 5c 70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 files\passwords.txt
		$a_01_7 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d } //1 /c taskkill /im
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}