
rule Trojan_Win32_ClickFix_SEZ1{
	meta:
		description = "Trojan:Win32/ClickFix.SEZ1,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 [0-20] 68 00 74 00 74 00 70 00 [0-10] 30 00 78 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}