
rule Trojan_BAT_Rhadamanthus_ABYX_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthus.ABYX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 0d 00 00 70 28 90 01 01 00 00 06 0a 28 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 0b dd 90 01 01 00 00 00 26 de d6 07 2a 90 00 } //01 00 
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //00 00 
	condition:
		any of ($a_*)
 
}