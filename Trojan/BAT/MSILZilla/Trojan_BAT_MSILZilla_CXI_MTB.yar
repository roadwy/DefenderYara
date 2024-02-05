
rule Trojan_BAT_MSILZilla_CXI_MTB{
	meta:
		description = "Trojan:BAT/MSILZilla.CXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 09 18 5b 06 09 18 6f 90 01 04 1f 10 28 1c 90 01 03 9c 09 18 58 0d 09 07 32 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}