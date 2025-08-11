
rule Trojan_Win32_ClickFix_FFK_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.FFK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6d 00 2a 00 74 00 61 00 2e 00 2a 00 65 00 } //1 m*ta.*e
		$a_00_1 = {7c 00 20 00 69 00 45 00 58 00 } //1 | iEX
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}