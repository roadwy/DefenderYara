
rule Trojan_AndroidOS_Fakeapp_RE{
	meta:
		description = "Trojan:AndroidOS/Fakeapp.RE,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 66 37 30 66 63 34 38 63 64 39 62 62 65 33 39 65 37 34 65 31 66 63 37 34 35 39 36 35 35 32 62 } //1 ef70fc48cd9bbe39e74e1fc74596552b
		$a_01_1 = {63 72 79 70 74 6f 6d 69 6e 65 72 2e 62 69 74 63 6f 69 6e 6d 69 6e 65 72 2e 75 69 2e 68 69 73 74 6f 72 79 } //1 cryptominer.bitcoinminer.ui.history
		$a_01_2 = {76 70 6e 6d 61 73 74 65 72 66 72 65 65 2e 76 70 6e 6d 61 73 74 65 72 70 72 6f 78 79 } //1 vpnmasterfree.vpnmasterproxy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}