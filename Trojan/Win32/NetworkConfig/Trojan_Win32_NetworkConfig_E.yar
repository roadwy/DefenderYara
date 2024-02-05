
rule Trojan_Win32_NetworkConfig_E{
	meta:
		description = "Trojan:Win32/NetworkConfig.E,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {69 00 70 00 63 00 6f 00 6e 00 66 00 69 00 67 00 90 02 10 2f 00 61 00 6c 00 6c 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}