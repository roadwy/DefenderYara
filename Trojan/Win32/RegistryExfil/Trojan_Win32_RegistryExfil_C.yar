
rule Trojan_Win32_RegistryExfil_C{
	meta:
		description = "Trojan:Win32/RegistryExfil.C,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 } //0a 00 
		$a_00_1 = {68 00 6b 00 6c 00 6d 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 } //01 00 
		$a_00_2 = {63 00 6f 00 70 00 79 00 } //01 00 
		$a_00_3 = {73 00 61 00 76 00 65 00 } //01 00 
		$a_00_4 = {65 00 78 00 70 00 6f 00 72 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}