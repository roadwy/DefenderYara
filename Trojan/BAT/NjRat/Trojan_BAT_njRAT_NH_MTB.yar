
rule Trojan_BAT_njRAT_NH_MTB{
	meta:
		description = "Trojan:BAT/njRAT.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 07 08 11 07 6f ?? 00 00 0a 11 05 11 07 02 58 11 06 5d 93 61 d1 d1 9d 17 11 07 58 13 07 19 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}