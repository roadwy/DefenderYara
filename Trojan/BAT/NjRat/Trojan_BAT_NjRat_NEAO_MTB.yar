
rule Trojan_BAT_NjRat_NEAO_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {28 4a 00 00 0a 0b 72 90 01 02 00 70 07 73 90 01 01 00 00 0a 0c 08 02 6f 90 01 01 00 00 0a 74 90 01 01 00 00 1b 28 90 01 01 00 00 06 0a 2b 00 06 2a 90 00 } //05 00 
		$a_01_1 = {44 65 74 65 63 74 56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 } //00 00  DetectVirtualMachine
	condition:
		any of ($a_*)
 
}