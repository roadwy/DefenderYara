
rule Trojan_Win32_BitsAdmin_ZY{
	meta:
		description = "Trojan:Win32/BitsAdmin.ZY,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 } //5 bitsadmin
		$a_00_1 = {2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 } //5 /transfer
		$a_02_2 = {24 00 5c 00 90 02 30 2e 00 65 00 78 00 65 00 90 00 } //1
		$a_02_3 = {24 00 5c 00 90 02 30 2e 00 64 00 6c 00 6c 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=11
 
}