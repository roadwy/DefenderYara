
rule Trojan_Win32_NetUseSpray_A_cbl4{
	meta:
		description = "Trojan:Win32/NetUseSpray.A!cbl4,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-40] 75 00 73 00 65 00 [0-40] 5c 00 5c 00 } //1
		$a_02_1 = {6e 00 65 00 74 00 20 00 [0-40] 75 00 73 00 65 00 [0-40] 5c 00 5c 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}