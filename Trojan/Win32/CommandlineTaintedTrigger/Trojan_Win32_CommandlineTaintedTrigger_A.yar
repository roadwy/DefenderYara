
rule Trojan_Win32_CommandlineTaintedTrigger_A{
	meta:
		description = "Trojan:Win32/CommandlineTaintedTrigger.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 00 73 00 74 00 61 00 69 00 6e 00 74 00 65 00 64 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 61 00 } //00 00  istaintedmachinea
	condition:
		any of ($a_*)
 
}