
rule Trojan_Win32_Vidar_EC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 5c 53 74 65 61 6d 5c 73 74 65 61 6d 5f 74 6f 6b 65 6e 73 2e 74 78 74 } //1 Soft\Steam\steam_tokens.txt
		$a_81_1 = {69 6e 66 6f 72 6d 61 74 69 6f 6e 2e 74 78 74 } //1 information.txt
		$a_81_2 = {77 61 6c 6c 65 74 5f 70 61 74 68 } //1 wallet_path
		$a_81_3 = {74 2e 6d 65 2f 69 79 69 67 75 6e 6c } //1 t.me/iyigunl
		$a_81_4 = {4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 2e 6b 65 79 73 } //1 Monero\wallet.keys
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}