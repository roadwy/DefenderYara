
rule Trojan_BAT_Nanocore_NCC_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 09 11 03 28 2e 00 00 06 20 90 01 03 00 7e 90 01 03 04 7b 90 01 03 04 39 90 01 03 00 26 20 90 01 03 00 38 90 01 03 00 fe 90 01 02 00 90 00 } //01 00 
		$a_01_1 = {43 6d 75 76 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  Cmuvk.Properties.Resources
	condition:
		any of ($a_*)
 
}