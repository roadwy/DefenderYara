
rule Trojan_Win32_ClickFix_BBO_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.BBO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 00 4c 00 65 00 6e 00 67 00 74 00 68 00 5d 00 29 00 2d 00 6a 00 6f 00 69 00 6e 00 27 00 27 00 3b 00 24 00 } //1 .Length])-join'';$
		$a_00_1 = {27 00 2c 00 27 00 27 00 29 00 } //1 ','')
		$a_00_2 = {5d 00 2b 00 27 00 } //1 ]+'
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}