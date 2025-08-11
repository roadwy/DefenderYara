
rule Trojan_Win32_ClickFix_DAO_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DAO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_00_1 = {2d 00 55 00 73 00 65 00 42 00 61 00 73 00 69 00 63 00 50 00 61 00 72 00 73 00 69 00 6e 00 67 00 29 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //5 -UseBasicParsing).Content
		$a_00_2 = {69 00 65 00 78 00 } //1 iex
		$a_00_3 = {69 00 77 00 72 00 } //1 iwr
		$a_00_4 = {24 00 5f 00 20 00 2d 00 62 00 78 00 6f 00 72 00 } //1 $_ -bxor
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=18
 
}