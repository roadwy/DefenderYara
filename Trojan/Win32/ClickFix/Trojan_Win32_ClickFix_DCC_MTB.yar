
rule Trojan_Win32_ClickFix_DCC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DCC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6e 00 6e 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 20 00 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 } //100 conhost --headless
		$a_00_1 = {77 00 6d 00 69 00 63 00 20 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 20 00 63 00 61 00 6c 00 6c 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 30 00 } //10 wmic product call install 0
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10) >=110
 
}