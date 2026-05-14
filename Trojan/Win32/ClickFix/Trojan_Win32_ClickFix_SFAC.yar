
rule Trojan_Win32_ClickFix_SFAC{
	meta:
		description = "Trojan:Win32/ClickFix.SFAC,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_02_2 = {66 00 69 00 6e 00 67 00 65 00 72 00 20 00 [0-ff] 40 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*10) >=11
 
}