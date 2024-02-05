
rule Trojan_Win32_MasqueradingRemoteAccessTool_A{
	meta:
		description = "Trojan:Win32/MasqueradingRemoteAccessTool.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}