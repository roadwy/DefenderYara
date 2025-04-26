
rule Trojan_Win64_IcedID_GE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 5c 63 72 79 70 74 45 52 52 44 6c 6c 2e 70 64 62 } //3 Dll\cryptERRDll.pdb
		$a_81_1 = {61 36 77 30 78 6b 6b 66 61 38 78 72 } //3 a6w0xkkfa8xr
		$a_81_2 = {61 6f 33 70 64 78 70 62 74 32 6c 32 6b 71 64 69 73 78 73 33 71 6c 73 } //3 ao3pdxpbt2l2kqdisxs3qls
		$a_81_3 = {49 6e 74 65 72 6e 65 74 43 61 6e 6f 6e 69 63 61 6c 69 7a 65 55 72 6c 41 } //3 InternetCanonicalizeUrlA
		$a_81_4 = {48 74 74 70 41 64 64 52 65 71 75 65 73 74 48 65 61 64 65 72 73 41 } //3 HttpAddRequestHeadersA
		$a_81_5 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //3 HttpSendRequestA
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=13
 
}