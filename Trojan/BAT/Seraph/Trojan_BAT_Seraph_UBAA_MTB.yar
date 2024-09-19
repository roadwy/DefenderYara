
rule Trojan_BAT_Seraph_UBAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.UBAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 1d 58 1d 59 91 61 03 06 1a 58 4a 20 10 02 00 00 58 20 0f 02 00 00 59 03 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 1b 58 1b 59 91 59 20 fc 00 00 00 58 1a 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}