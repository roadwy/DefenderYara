
rule Trojan_Win32_SuspClickFix_V{
	meta:
		description = "Trojan:Win32/SuspClickFix.V,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 } //3
		$a_00_1 = {2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 } //1 --headless
		$a_00_2 = {20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2f 00 6d 00 69 00 6e 00 20 00 } //1  /c start /min 
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=5
 
}