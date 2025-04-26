
rule Trojan_Win32_SuspWmiUsage_ZPB{
	meta:
		description = "Trojan:Win32/SuspWmiUsage.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {77 00 6d 00 69 00 63 00 } //1 wmic
		$a_00_1 = {70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 67 00 65 00 74 00 20 00 63 00 61 00 70 00 74 00 69 00 6f 00 6e 00 } //1 process get caption
		$a_00_2 = {65 00 78 00 65 00 63 00 75 00 74 00 61 00 62 00 6c 00 65 00 70 00 61 00 74 00 68 00 } //1 executablepath
		$a_00_3 = {63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 6c 00 69 00 6e 00 65 00 } //1 commandline
		$a_00_4 = {2f 00 66 00 6f 00 72 00 6d 00 61 00 74 00 3a 00 } //1 /format:
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}