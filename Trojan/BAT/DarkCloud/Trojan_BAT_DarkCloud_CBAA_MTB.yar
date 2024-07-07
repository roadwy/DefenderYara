
rule Trojan_BAT_DarkCloud_CBAA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.CBAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 28 90 01 01 01 00 06 1f 10 28 90 01 01 01 00 06 9c 11 05 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}