
rule Trojan_Win32_SuspClickFix_R3{
	meta:
		description = "Trojan:Win32/SuspClickFix.R3,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 } //3
		$a_00_1 = {7c 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 | powershell
		$a_00_2 = {7c 00 20 00 63 00 6d 00 64 00 20 00 26 00 26 00 } //1 | cmd &&
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=5
 
}