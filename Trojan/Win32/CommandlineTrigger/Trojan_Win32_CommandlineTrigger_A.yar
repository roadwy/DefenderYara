
rule Trojan_Win32_CommandlineTrigger_A{
	meta:
		description = "Trojan:Win32/CommandlineTrigger.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 00 73 00 74 00 65 00 73 00 74 00 34 00 35 00 36 00 } //00 00 
	condition:
		any of ($a_*)
 
}