
rule Trojan_Win32_Shimming_A{
	meta:
		description = "Trojan:Win32/Shimming.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {73 64 62 69 6e 73 74 20 2d 71 } //sdbinst -q  1
		$a_80_1 = {61 69 5f 73 68 69 6d 5f 74 65 73 74 2e 73 64 62 } //ai_shim_test.sdb  1
		$a_80_2 = {73 64 62 69 6e 73 74 20 2d 71 20 2d 75 } //sdbinst -q -u  -10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*-10) >=2
 
}