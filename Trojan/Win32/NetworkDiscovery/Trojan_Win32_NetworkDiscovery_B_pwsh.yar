
rule Trojan_Win32_NetworkDiscovery_B_pwsh{
	meta:
		description = "Trojan:Win32/NetworkDiscovery.B!pwsh,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {67 00 65 00 74 00 2d 00 6e 00 65 00 74 00 74 00 63 00 70 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //1 get-nettcpconnection
	condition:
		((#a_00_0  & 1)*1) >=1
 
}