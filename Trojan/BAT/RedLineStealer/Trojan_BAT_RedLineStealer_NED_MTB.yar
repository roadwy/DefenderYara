
rule Trojan_BAT_RedLineStealer_NED_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.NED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 6f 25 90 01 03 03 07 03 6f 90 01 04 5d 6f 90 01 04 61 0c 06 72 90 01 04 08 28 90 01 04 6f 90 01 04 26 07 17 58 0b 07 02 6f 90 01 04 32 ca 90 00 } //1
		$a_01_1 = {46 00 6f 00 61 00 6d 00 69 00 6c 00 79 00 } //1 Foamily
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}