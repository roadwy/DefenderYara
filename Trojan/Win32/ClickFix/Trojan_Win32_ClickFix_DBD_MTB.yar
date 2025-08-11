
rule Trojan_Win32_ClickFix_DBD_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DBD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_02_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 3a 00 [0-0a] 2f 00 } //5
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*5) >=15
 
}