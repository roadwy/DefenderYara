
rule Trojan_Win32_PersistenceRegistryPowershell{
	meta:
		description = "Trojan:Win32/PersistenceRegistryPowershell,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}