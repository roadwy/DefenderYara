
rule Trojan_Win32_LummaStealerClick_I{
	meta:
		description = "Trojan:Win32/LummaStealerClick.I,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {68 00 74 00 74 00 70 00 [0-3c] 7c 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 } //10
		$a_00_1 = {69 00 65 00 78 00 } //10 iex
		$a_00_2 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_3 = {6d 00 2a 00 74 00 61 00 2e 00 65 00 } //1 m*ta.e
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=21
 
}