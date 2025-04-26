
rule Trojan_Win32_CommandlineTaintedTrigger_C_high{
	meta:
		description = "Trojan:Win32/CommandlineTaintedTrigger.C!high,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {69 00 73 00 74 00 61 00 69 00 6e 00 74 00 65 00 64 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 6d 00 6c 00 5f 00 68 00 69 00 67 00 68 00 } //1 istaintedmachineml_high
	condition:
		((#a_00_0  & 1)*1) >=1
 
}