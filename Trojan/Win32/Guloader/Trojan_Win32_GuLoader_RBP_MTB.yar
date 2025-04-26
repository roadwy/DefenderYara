
rule Trojan_Win32_GuLoader_RBP_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {72 65 73 70 6f 6e 64 65 6e 74 65 72 6e 65 20 76 61 6c 67 66 6c 73 6b 65 74 73 20 64 65 66 61 63 65 72 } //1 respondenterne valgflskets defacer
		$a_81_1 = {6e 6f 6e 61 6c 6c 69 74 65 72 61 74 69 76 65 6c 79 } //1 nonalliteratively
		$a_81_2 = {64 61 77 74 20 69 6e 74 65 72 61 72 6d 79 } //1 dawt interarmy
		$a_81_3 = {6c 6f 75 64 6c 69 65 73 74 } //1 loudliest
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}