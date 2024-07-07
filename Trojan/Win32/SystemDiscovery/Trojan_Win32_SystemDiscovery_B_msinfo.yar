
rule Trojan_Win32_SystemDiscovery_B_msinfo{
	meta:
		description = "Trojan:Win32/SystemDiscovery.B!msinfo,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6d 00 73 00 69 00 6e 00 66 00 6f 00 90 02 10 2f 00 6e 00 66 00 6f 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}