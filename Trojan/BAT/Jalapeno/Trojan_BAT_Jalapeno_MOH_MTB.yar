
rule Trojan_BAT_Jalapeno_MOH_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.MOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {04 1b 5d 2c 0d 09 1f 12 93 20 00 73 00 00 59 0c 2b cf 1b 2b fa 03 2b 07 03 20 c8 00 00 00 61 b4 0a 06 2a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}