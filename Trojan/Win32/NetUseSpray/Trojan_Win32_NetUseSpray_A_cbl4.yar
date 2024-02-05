
rule Trojan_Win32_NetUseSpray_A_cbl4{
	meta:
		description = "Trojan:Win32/NetUseSpray.A!cbl4,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 90 02 40 75 00 73 00 65 00 90 02 40 5c 00 5c 00 90 00 } //01 00 
		$a_02_1 = {6e 00 65 00 74 00 20 00 90 02 40 75 00 73 00 65 00 90 02 40 5c 00 5c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}