
rule Trojan_Win64_ChroHack_SB_MSR{
	meta:
		description = "Trojan:Win64/ChroHack.SB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 00 66 00 75 00 6f 00 63 00 6f 00 6c 00 65 00 6e 00 74 00 6f 00 2e 00 69 00 74 00 2f 00 77 00 70 00 2d 00 69 00 6e 00 63 00 6c 00 75 00 64 00 65 00 73 00 } //1 afuocolento.it/wp-includes
		$a_01_1 = {53 00 65 00 74 00 2d 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 } //1 Set-Cookie
		$a_01_2 = {43 72 61 74 43 6c 69 65 6e 74 2e 64 6c 6c } //1 CratClient.dll
		$a_01_3 = {61 00 74 00 6c 00 54 00 72 00 61 00 63 00 65 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 } //1 atlTraceSecurity
		$a_01_4 = {61 00 74 00 6c 00 54 00 72 00 61 00 63 00 65 00 43 00 61 00 63 00 68 00 65 00 } //1 atlTraceCache
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}