
rule Trojan_BAT_Seraph_IAAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.IAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 07 06 1a 58 4a 07 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 61 03 06 1a 58 4a 20 ?? ?? 00 00 58 20 ?? ?? 00 00 59 03 8e 69 5d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}