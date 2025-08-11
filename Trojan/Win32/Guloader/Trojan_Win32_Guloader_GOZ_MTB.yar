
rule Trojan_Win32_Guloader_GOZ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {74 72 65 76 6c 65 72 73 20 70 69 7a 7a 61 70 61 6b 6b 65 20 67 72 75 6e 64 6b 75 72 73 65 74 73 } //1 trevlers pizzapakke grundkursets
		$a_81_1 = {6c 6f 67 65 72 65 64 65 73 20 76 61 72 69 } //1 logeredes vari
		$a_81_2 = {73 79 64 6b 6f 72 65 61 6e 65 72 65 6e } //1 sydkoreaneren
		$a_81_3 = {4b 6e 73 64 69 73 6b 72 69 6d 69 6e 65 72 65 64 65 73 2e 74 61 6e } //1 Knsdiskrimineredes.tan
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}