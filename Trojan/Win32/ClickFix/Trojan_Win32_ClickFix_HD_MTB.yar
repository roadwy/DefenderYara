
rule Trojan_Win32_ClickFix_HD_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_1 = {68 00 74 00 74 00 70 00 } //10 http
		$a_00_2 = {2e 00 68 00 74 00 61 00 } //-10 .hta
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*10+(#a_00_2  & 1)*-10) >=11
 
}