
rule Trojan_BAT_Zusy_GPS_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 50 07 02 50 8e 69 5d 02 50 07 02 50 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? 00 00 0a 02 50 07 17 58 02 50 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c 07 17 58 0b 07 02 50 8e 69 17 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}