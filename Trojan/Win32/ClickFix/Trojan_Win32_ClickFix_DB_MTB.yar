
rule Trojan_Win32_ClickFix_DB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {2e 00 68 00 74 00 6d 00 6c 00 20 00 23 00 } //1 .html #
		$a_00_3 = {76 00 65 00 72 00 69 00 66 00 } //1 verif
		$a_00_4 = {2d 00 20 00 72 00 61 00 79 00 } //1 - ray
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}