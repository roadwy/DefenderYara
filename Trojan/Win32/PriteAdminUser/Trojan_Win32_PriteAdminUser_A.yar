
rule Trojan_Win32_PriteAdminUser_A{
	meta:
		description = "Trojan:Win32/PriteAdminUser.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {6e 00 65 00 74 00 20 00 6c 00 6f 00 63 00 61 00 6c 00 67 00 72 00 6f 00 75 00 70 00 } //2 net localgroup
		$a_00_1 = {2f 00 61 00 64 00 64 00 } //1 /add
		$a_00_2 = {61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 73 00 } //1 administrators
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}