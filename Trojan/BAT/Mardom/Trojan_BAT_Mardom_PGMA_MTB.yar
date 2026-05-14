
rule Trojan_BAT_Mardom_PGMA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.PGMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 1a 5a 18 58 58 47 0d 02 7b 07 00 00 04 07 08 58 20 ff 00 00 00 09 59 1f 72 61 d2 9c 08 17 58 0c 08 02 7b 06 00 00 04 3f d2 ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}