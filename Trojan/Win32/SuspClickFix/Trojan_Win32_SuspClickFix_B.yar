
rule Trojan_Win32_SuspClickFix_B{
	meta:
		description = "Trojan:Win32/SuspClickFix.B,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_2 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_3 = {2d 00 2d 00 75 00 72 00 6c 00 20 00 68 00 74 00 74 00 70 00 } //-10 --url http
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-10) >=2
 
}