
rule Trojan_BAT_DarkVision_APJA_MTB{
	meta:
		description = "Trojan:BAT/DarkVision.APJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 91 61 03 06 1a 58 4a 20 0b 02 00 00 58 20 0a 02 00 00 59 1f 09 59 1f 09 58 03 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}