
rule Trojan_BAT_SmokeLoader_RS_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 02 13 04 38 1e 00 00 00 38 45 00 00 00 38 8f 00 00 00 11 01 8e 69 17 da 17 d6 8d 7e 00 00 01 13 02 38 73 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}