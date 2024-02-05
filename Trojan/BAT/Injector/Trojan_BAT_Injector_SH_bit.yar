
rule Trojan_BAT_Injector_SH_bit{
	meta:
		description = "Trojan:BAT/Injector.SH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 00 69 00 74 00 74 00 65 00 6e 00 } //01 00 
		$a_00_1 = {56 00 69 00 72 00 74 00 6f 00 } //01 00 
		$a_03_2 = {06 1b 58 7e 90 02 06 8e 69 58 90 01 01 7e 90 02 07 91 90 01 01 7e 90 02 07 1f 1d 5d 91 90 01 01 1f 1f 5f 63 90 01 02 28 90 02 06 13 04 7e 90 02 08 11 04 28 90 02 06 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}