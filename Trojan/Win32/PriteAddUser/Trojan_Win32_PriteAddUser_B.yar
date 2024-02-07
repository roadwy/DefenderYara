
rule Trojan_Win32_PriteAddUser_B{
	meta:
		description = "Trojan:Win32/PriteAddUser.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 00 61 00 64 00 64 00 } //01 00  /add
		$a_00_1 = {6e 00 65 00 74 00 20 00 75 00 73 00 65 00 72 00 20 00 } //00 00  net user 
	condition:
		any of ($a_*)
 
}