
rule Trojan_Win32_Predator_SO_{
	meta:
		description = "Trojan:Win32/Predator.SO!!Predator.SO!MTB,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {4c 6f 67 49 6e 66 6f 2e 74 78 74 } //1 LogInfo.txt
		$a_81_1 = {5c 70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 \passwords.txt
		$a_81_2 = {49 6e 73 74 61 6c 6c 65 64 20 53 6f 66 74 77 61 72 65 2e 74 78 74 } //1 Installed Software.txt
		$a_81_3 = {5c 66 6f 72 6d 73 2e 74 78 74 } //1 \forms.txt
		$a_81_4 = {43 72 79 70 74 6f 20 57 61 6c 6c 65 74 73 5c 57 61 6c 6c 65 74 49 6e 66 6f 2e 74 78 74 } //1 Crypto Wallets\WalletInfo.txt
		$a_81_5 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 41 75 74 68 79 20 44 65 73 6b 74 6f 70 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 2a 2e 6c 6f 63 61 6c 73 74 6f 72 61 67 65 } //1 Application Data\Authy Desktop\Local Storage\*.localstorage
		$a_81_6 = {5c 4e 6f 72 64 56 50 4e 5c 4e 6f 72 64 56 50 4e 2a } //1 \NordVPN\NordVPN*
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}