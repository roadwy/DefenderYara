
rule Trojan_BAT_FormBook_NS_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_81_0 = {37 62 38 66 63 38 61 63 2d 37 39 61 37 2d 34 30 64 62 2d 61 35 32 36 2d 61 36 38 63 65 61 63 39 31 61 64 61 } //5 7b8fc8ac-79a7-40db-a526-a68ceac91ada
		$a_81_1 = {55 72 6c 54 6f 6b 65 6e 44 65 63 6f 64 65 } //1 UrlTokenDecode
		$a_81_2 = {67 65 74 5f 55 73 65 72 6e 61 6d 65 } //1 get_Username
		$a_81_3 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //1 get_Password
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=9
 
}