
rule Trojan_Win32_SuspClickFix_E{
	meta:
		description = "Trojan:Win32/SuspClickFix.E,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 00 57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_02_1 = {20 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 20 00 63 00 61 00 6c 00 6c 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 [0-40] 68 00 74 00 74 00 70 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}