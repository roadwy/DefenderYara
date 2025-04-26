
rule Trojan_Win32_SuspWmiUsage_ZPC{
	meta:
		description = "Trojan:Win32/SuspWmiUsage.ZPC,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 00 6d 00 69 00 63 00 } //1 wmic
		$a_00_1 = {71 00 66 00 65 00 20 00 67 00 65 00 74 00 20 00 64 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 } //1 qfe get description
		$a_00_2 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 64 00 4f 00 6e 00 } //1 installedOn
		$a_00_3 = {2f 00 66 00 6f 00 72 00 6d 00 61 00 74 00 3a 00 } //1 /format:
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}