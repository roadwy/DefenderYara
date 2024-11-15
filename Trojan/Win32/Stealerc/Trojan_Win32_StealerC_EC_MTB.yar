
rule Trojan_Win32_StealerC_EC_MTB{
	meta:
		description = "Trojan:Win32/StealerC.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2e 74 61 67 67 61 6e 74 } //1 .taggant
		$a_81_1 = {77 61 6c 6c 65 74 5f 70 61 74 68 } //1 wallet_path
		$a_81_2 = {5c 4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 2e 6b 65 79 73 } //1 \Monero\wallet.keys
		$a_81_3 = {53 4f 46 54 57 41 52 45 5c 6d 6f 6e 65 72 6f 2d 70 72 6f 6a 65 63 74 5c 6d 6f 6e 65 72 6f 2d 63 6f 72 65 } //1 SOFTWARE\monero-project\monero-core
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}