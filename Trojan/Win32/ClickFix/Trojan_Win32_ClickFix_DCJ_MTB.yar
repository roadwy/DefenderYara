
rule Trojan_Win32_ClickFix_DCJ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DCJ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6e 00 6e 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d 00 6b 00 20 00 2d 00 53 00 73 00 20 00 2d 00 58 00 } //100 -k -Ss -X
		$a_00_1 = {26 00 26 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2f 00 6d 00 69 00 6e 00 } //10 && start /min
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10) >=110
 
}