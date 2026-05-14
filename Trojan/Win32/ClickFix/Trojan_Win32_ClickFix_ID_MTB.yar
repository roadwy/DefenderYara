
rule Trojan_Win32_ClickFix_ID_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.ID!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 20 00 2f 00 69 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-30] 2f 00 6d 00 73 00 69 00 2f 00 90 23 20 06 61 2d 7a 30 2d 39 20 00 2f 00 71 00 6e 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}