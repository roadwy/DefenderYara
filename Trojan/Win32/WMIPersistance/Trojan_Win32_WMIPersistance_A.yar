
rule Trojan_Win32_WMIPersistance_A{
	meta:
		description = "Trojan:Win32/WMIPersistance.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_02_0 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 77 00 62 00 65 00 6d 00 5c 00 6d 00 6f 00 66 00 63 00 6f 00 6d 00 70 00 2e 00 65 00 78 00 65 00 [0-09] 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 [0-20] 2e 00 6d 00 6f 00 66 00 } //3
	condition:
		((#a_02_0  & 1)*3) >=3
 
}