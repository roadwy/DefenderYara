
rule Trojan_BAT_RatX_RDA_MTB{
	meta:
		description = "Trojan:BAT/RatX.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 75 4c 00 00 01 6f b1 00 00 0a 1e 9a 0b 07 0a 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}