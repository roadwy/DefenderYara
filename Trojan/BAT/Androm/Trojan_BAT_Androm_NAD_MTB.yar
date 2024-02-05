
rule Trojan_BAT_Androm_NAD_MTB{
	meta:
		description = "Trojan:BAT/Androm.NAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {1f 10 6f 82 00 00 06 20 90 01 03 00 38 90 01 03 ff 11 07 16 8c 90 01 03 01 7e 90 01 03 04 13 10 11 10 6f 90 01 03 0a 26 38 90 01 03 ff 02 7b 90 01 03 04 16 28 90 01 03 06 20 90 01 03 00 38 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {47 4e 4f 4c 43 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}