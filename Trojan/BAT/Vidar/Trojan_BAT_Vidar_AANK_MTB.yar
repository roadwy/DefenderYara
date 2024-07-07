
rule Trojan_BAT_Vidar_AANK_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AANK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 25 08 28 90 01 01 00 00 06 25 17 28 90 01 01 00 00 06 25 18 28 90 01 01 00 00 06 25 06 28 90 01 01 00 00 06 28 90 01 01 00 00 06 07 16 07 8e 69 6f 90 01 01 00 00 0a 0d 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}