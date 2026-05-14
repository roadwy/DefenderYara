
rule Trojan_Win32_ClickFix_IK_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.IK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_02_0 = {69 00 65 00 78 00 28 00 69 00 77 00 72 00 20 00 2d 00 75 00 72 00 69 00 20 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 20 00 2d 00 75 00 73 00 65 00 62 00 61 00 73 00 69 00 63 00 70 00 61 00 72 00 73 00 69 00 6e 00 67 00 29 00 } //5
		$a_00_1 = {70 00 72 00 65 00 73 00 73 00 20 00 } //1 press 
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*1) >=6
 
}