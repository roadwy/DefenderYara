
rule Trojan_Win32_LummaStealerClick_W_MTB{
	meta:
		description = "Trojan:Win32/LummaStealerClick.W!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 } //10 http
		$a_00_1 = {70 00 68 00 70 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 } //10 php?action
		$a_00_2 = {69 00 65 00 78 00 } //1 iex
		$a_00_3 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //1 invoke-expression
		$a_00_4 = {69 00 77 00 72 00 } //1 iwr
		$a_00_5 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 } //1 invoke-webrequest
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=22
 
}