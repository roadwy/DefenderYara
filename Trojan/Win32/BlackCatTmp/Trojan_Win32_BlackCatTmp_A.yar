
rule Trojan_Win32_BlackCatTmp_A{
	meta:
		description = "Trojan:Win32/BlackCatTmp.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 } //1 bcdedit
		$a_00_1 = {2f 00 73 00 65 00 74 00 } //1 /set
		$a_00_2 = {73 00 61 00 66 00 65 00 62 00 6f 00 6f 00 74 00 } //1 safeboot
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}