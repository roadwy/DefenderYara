
rule Trojan_Win32_Mestap_A{
	meta:
		description = "Trojan:Win32/Mestap.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 00 62 00 6f 00 75 00 74 00 3a 00 3c 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00 } //01 00 
		$a_00_1 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 22 00 48 00 4b 00 43 00 55 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 } //00 00 
	condition:
		any of ($a_*)
 
}