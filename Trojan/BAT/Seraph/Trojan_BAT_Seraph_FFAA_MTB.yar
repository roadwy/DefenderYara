
rule Trojan_BAT_Seraph_FFAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.FFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 07 08 07 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 61 ?? 08 20 8a 10 00 00 58 20 89 10 00 00 59 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}