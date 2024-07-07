
rule Trojan_BAT_DarkCloud_NHAA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.NHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 1f 09 5d 16 fe 01 13 06 11 06 2c 0c 02 11 05 02 11 05 91 1f 36 61 b4 9c 11 05 17 d6 13 05 11 05 11 04 31 da } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}