
rule Trojan_Win32_PswStealer_C{
	meta:
		description = "Trojan:Win32/PswStealer.C,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffe8 03 ffffffd2 00 04 00 00 64 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //64 00 
		$a_00_1 = {20 00 70 00 61 00 73 00 73 00 } //64 00 
		$a_00_2 = {20 00 70 00 73 00 77 00 } //0a 00 
		$a_00_3 = {63 00 6f 00 70 00 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}