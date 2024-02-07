
rule Trojan_BAT_Quasar_DHE_MTB{
	meta:
		description = "Trojan:BAT/Quasar.DHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 90 01 04 02 07 17 58 02 8e 69 5d 91 28 90 01 04 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 04 9c 07 17 58 0b 07 02 8e 69 31 bb 90 00 } //01 00 
		$a_01_1 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}