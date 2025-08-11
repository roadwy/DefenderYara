
rule Trojan_Win64_Stealer_NFA_MTB{
	meta:
		description = "Trojan:Win64/Stealer.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {25 73 5c 77 61 6c 6c 65 74 5f 64 75 6d 70 5f 25 73 } //1 %s\wallet_dump_%s
		$a_81_1 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
		$a_81_2 = {43 72 65 64 65 6e 74 69 61 6c 73 2f 4d 69 63 72 6f 73 6f 66 74 5f 4d 61 69 6c 2e 74 78 74 } //2 Credentials/Microsoft_Mail.txt
		$a_81_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 25 73 5c 4f 75 74 6c 6f 6f 6b 5c 50 72 6f 66 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b } //1 Software\Microsoft\Office\%s\Outlook\Profiles\Outlook
		$a_81_4 = {42 72 61 76 65 57 61 6c 6c 65 74 } //1 BraveWallet
		$a_81_5 = {45 78 6f 64 75 73 } //1 Exodus
		$a_81_6 = {25 73 5c 6b 61 74 7a 5f 6f 6e 74 6f 70 2e 64 6c 6c } //1 %s\katz_ontop.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}