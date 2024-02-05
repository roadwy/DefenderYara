
rule Trojan_Win32_SystemOwnerDiscovery_C_qwinsta{
	meta:
		description = "Trojan:Win32/SystemOwnerDiscovery.C!qwinsta,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {71 00 77 00 69 00 6e 00 73 00 74 00 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}