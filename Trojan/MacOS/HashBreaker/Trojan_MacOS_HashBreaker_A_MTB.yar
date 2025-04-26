
rule Trojan_MacOS_HashBreaker_A_MTB{
	meta:
		description = "Trojan:MacOS/HashBreaker.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 61 74 61 2e 57 61 6c 6c 65 74 73 } //1 data.Wallets
		$a_01_1 = {4e 55 49 54 4b 41 5f 54 49 43 4b 45 52 } //1 NUITKA_TICKER
		$a_00_2 = {64 61 74 61 2e 63 68 61 69 6e 62 72 65 61 6b 65 72 } //1 data.chainbreaker
		$a_00_3 = {67 65 74 5f 63 6f 69 6e 6f 6d 69 } //1 get_coinomi
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Trojan_MacOS_HashBreaker_A_MTB_2{
	meta:
		description = "Trojan:MacOS/HashBreaker.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 75 6d 70 4b 65 79 43 68 61 69 6e } //1 DumpKeyChain
		$a_00_1 = {55 70 6c 6f 61 64 4b 65 79 63 68 61 69 6e } //1 UploadKeychain
		$a_00_2 = {44 65 63 72 79 70 74 4b 65 79 63 68 61 69 6e } //1 DecryptKeychain
		$a_00_3 = {45 78 74 72 61 63 74 53 61 66 65 53 74 6f 72 61 67 65 50 61 73 73 77 6f 72 64 } //1 ExtractSafeStoragePassword
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}