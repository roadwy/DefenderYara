
rule Trojan_Win32_ClickFix_DBM_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DBM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-07] 2d 00 77 00 20 00 68 00 } //100
		$a_00_1 = {29 00 20 00 7c 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 ) | powershell
		$a_00_2 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*1) >=201
 
}