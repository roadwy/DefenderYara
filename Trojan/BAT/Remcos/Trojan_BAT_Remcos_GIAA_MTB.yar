
rule Trojan_BAT_Remcos_GIAA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.GIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 25 00 7e 90 01 01 00 00 04 07 7e 90 01 01 00 00 04 07 91 17 8d 90 01 01 00 00 01 25 16 1f 5d 9c 07 17 5d 91 61 d2 9c 00 07 17 58 0b 07 7e 90 01 01 00 00 04 8e 69 fe 04 0c 08 2d cd 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}