
rule Trojan_Win32_ClickFix_RXH_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.RXH!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,12 00 12 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10 powershell
		$a_00_1 = {29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 27 00 } //5 ).Downlo'
		$a_00_2 = {68 00 74 00 74 00 70 00 } //2 http
		$a_00_3 = {2d 00 4a 00 6f 00 69 00 6e 00 } //1 -Join
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1) >=18
 
}