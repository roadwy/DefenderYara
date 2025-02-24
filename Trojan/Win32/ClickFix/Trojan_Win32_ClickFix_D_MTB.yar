
rule Trojan_Win32_ClickFix_D_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.D!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_02_1 = {68 00 74 00 74 00 70 00 [0-02] 3a 00 2f 00 2f 00 } //1
		$a_00_2 = {72 00 65 00 63 00 61 00 70 00 74 00 63 00 68 00 61 00 } //1 recaptcha
		$a_00_3 = {76 00 65 00 72 00 69 00 66 00 } //1 verif
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}