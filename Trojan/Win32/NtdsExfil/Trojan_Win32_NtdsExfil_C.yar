
rule Trojan_Win32_NtdsExfil_C{
	meta:
		description = "Trojan:Win32/NtdsExfil.C,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffe8 03 6e 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4e 00 74 00 64 00 73 00 41 00 75 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 } //0a 00 
		$a_00_1 = {6e 00 74 00 64 00 73 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 } //64 00 
		$a_00_2 = {2d 00 2d 00 64 00 75 00 6d 00 70 00 2d 00 72 00 65 00 76 00 65 00 72 00 73 00 69 00 62 00 6c 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}