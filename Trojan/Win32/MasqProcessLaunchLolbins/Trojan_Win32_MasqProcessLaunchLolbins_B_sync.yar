
rule Trojan_Win32_MasqProcessLaunchLolbins_B_sync{
	meta:
		description = "Trojan:Win32/MasqProcessLaunchLolbins.B!sync,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_2 = {5c 00 73 00 63 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_3 = {5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=1
 
}