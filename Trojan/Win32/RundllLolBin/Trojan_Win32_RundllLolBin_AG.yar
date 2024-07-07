
rule Trojan_Win32_RundllLolBin_AG{
	meta:
		description = "Trojan:Win32/RundllLolBin.AG,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //1 bitsadmin.exe
		$a_00_1 = {74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 } //1 transfer
		$a_00_2 = {68 00 74 00 74 00 70 00 73 00 } //1 https
		$a_00_3 = {2e 00 78 00 6c 00 73 00 } //1 .xls
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}