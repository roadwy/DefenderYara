
rule Trojan_Win64_EvelynStealer_KX_MTB{
	meta:
		description = "Trojan:Win64/EvelynStealer.KX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {45 76 65 6c 79 6e 2f 31 2e 30 } //1 Evelyn/1.0
		$a_81_1 = {61 62 65 5f 64 65 63 72 79 70 74 2e 64 6c 6c } //1 abe_decrypt.dll
		$a_81_2 = {5c 61 62 65 5f 64 65 63 72 79 70 74 5f 6e 6f 5f 63 6f 6e 66 69 67 5f 65 72 72 6f 72 2e 74 78 74 } //1 \abe_decrypt_no_config_error.txt
		$a_81_3 = {45 76 65 6c 79 6e 20 66 6f 6c 64 65 72 3a 20 25 73 } //1 Evelyn folder: %s
		$a_81_4 = {43 6f 70 79 69 6e 67 20 77 61 6c 6c 65 74 73 20 74 6f 20 45 76 65 6c 79 6e 5c 57 61 6c 6c 65 74 73 2e 2e 2e } //1 Copying wallets to Evelyn\Wallets...
		$a_81_5 = {53 74 65 61 6c 69 6e 67 20 57 68 61 74 73 41 70 70 20 73 65 73 73 69 6f 6e 2e 2e 2e } //1 Stealing WhatsApp session...
		$a_81_6 = {53 74 65 61 6c 69 6e 67 20 54 65 6c 65 67 72 61 6d 20 73 65 73 73 69 6f 6e 2e 2e 2e } //1 Stealing Telegram session...
		$a_81_7 = {45 64 67 65 20 69 6e 6a 65 63 74 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c } //1 Edge injection successful
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}