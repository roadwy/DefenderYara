
rule Trojan_BAT_Marsilia_PTBC_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.PTBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 e2 00 00 70 0b 06 7e 01 00 00 04 72 01 00 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 00 07 16 28 90 01 01 00 00 0a 72 73 01 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 00 72 8f 01 00 70 0c 08 28 90 01 01 00 00 06 0d 09 2c 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}