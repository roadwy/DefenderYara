
rule Trojan_Win32_NetworkConfig_A{
	meta:
		description = "Trojan:Win32/NetworkConfig.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_02_0 = {6e 00 62 00 74 00 73 00 74 00 61 00 74 00 [0-10] 2d 00 6e 00 } //1
		$a_02_1 = {6e 00 6c 00 74 00 65 00 73 00 74 00 [0-10] 2f 00 64 00 63 00 } //1
		$a_02_2 = {6e 00 65 00 74 00 73 00 74 00 61 00 74 00 [0-10] 2d 00 6e 00 } //1
		$a_02_3 = {6e 00 65 00 74 00 73 00 74 00 61 00 74 00 [0-10] 2d 00 73 00 } //1
		$a_02_4 = {72 00 6f 00 75 00 74 00 65 00 [0-10] 70 00 72 00 69 00 6e 00 74 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=1
 
}