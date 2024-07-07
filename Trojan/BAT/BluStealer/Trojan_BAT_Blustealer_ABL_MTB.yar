
rule Trojan_BAT_Blustealer_ABL_MTB{
	meta:
		description = "Trojan:BAT/Blustealer.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 2b 31 02 08 91 0d 08 1f 0e 5d 13 04 03 11 04 9a 13 05 02 08 11 05 09 28 90 01 03 06 9c 08 04 fe 01 13 06 11 06 2c 07 28 90 01 03 0a 0a 00 00 08 17 d6 0c 08 07 31 cb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}