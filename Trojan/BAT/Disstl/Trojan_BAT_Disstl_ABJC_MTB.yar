
rule Trojan_BAT_Disstl_ABJC_MTB{
	meta:
		description = "Trojan:BAT/Disstl.ABJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 16 73 90 01 03 0a 0c 73 90 01 03 0a 0d 08 09 28 90 01 03 06 09 16 6a 6f 90 01 03 0a 09 13 04 de 1c 08 2c 06 08 6f 90 01 03 0a dc 90 0a 34 00 06 02 6f 90 00 } //01 00 
		$a_01_1 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //01 00  GetManifestResourceStream
		$a_01_2 = {54 00 69 00 6d 00 65 00 72 00 5f 00 52 00 65 00 73 00 6f 00 6c 00 75 00 74 00 69 00 6f 00 6e 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  Timer_Resolution.Properties.Resources
	condition:
		any of ($a_*)
 
}