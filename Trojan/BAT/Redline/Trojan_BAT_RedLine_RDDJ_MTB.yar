
rule Trojan_BAT_RedLine_RDDJ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 04 16 11 04 8e 69 6f a1 00 00 0a 13 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}