
rule Trojan_MacOS_HzRat_A_MTB{
	meta:
		description = "Trojan:MacOS/HzRat.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 72 6f 6a 61 6e 31 33 64 6f 77 6e 6c 6f 61 64 5f 66 69 6c 65 } //1 trojan13download_file
		$a_01_1 = {74 72 6f 6a 61 6e 31 35 65 78 65 63 75 74 65 5f 63 6d 64 6c 69 6e 65 } //1 trojan15execute_cmdline
		$a_01_2 = {74 72 6f 6a 61 6e 31 31 73 65 6e 64 5f 63 6f 6f 6b 69 65 } //1 trojan11send_cookie
		$a_01_3 = {74 72 6f 6a 61 6e 39 58 6f 72 4d 65 6d 6f 72 79 45 50 } //1 trojan9XorMemoryEP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}