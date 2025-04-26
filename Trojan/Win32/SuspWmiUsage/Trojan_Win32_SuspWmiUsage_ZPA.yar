
rule Trojan_Win32_SuspWmiUsage_ZPA{
	meta:
		description = "Trojan:Win32/SuspWmiUsage.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {77 00 6d 00 69 00 63 00 } //1 wmic
		$a_00_1 = {75 00 73 00 65 00 72 00 61 00 63 00 63 00 6f 00 75 00 6e 00 74 00 20 00 67 00 65 00 74 00 20 00 2f 00 41 00 4c 00 4c 00 20 00 2f 00 66 00 6f 00 72 00 6d 00 61 00 74 00 3a 00 } //1 useraccount get /ALL /format:
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}