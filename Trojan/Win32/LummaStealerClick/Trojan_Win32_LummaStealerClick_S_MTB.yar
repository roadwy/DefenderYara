
rule Trojan_Win32_LummaStealerClick_S_MTB{
	meta:
		description = "Trojan:Win32/LummaStealerClick.S!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_00_1 = {68 00 74 00 74 00 70 00 } //10 http
		$a_00_2 = {74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 } //10 telegram
		$a_00_3 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 72 00 65 00 73 00 74 00 6d 00 65 00 74 00 68 00 6f 00 64 00 20 00 2d 00 75 00 72 00 69 00 } //1 invoke-restmethod -uri
		$a_00_4 = {69 00 77 00 72 00 20 00 2d 00 75 00 72 00 69 00 } //1 iwr -uri
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=31
 
}