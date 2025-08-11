
rule Trojan_BAT_LokiBot_AY_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 05 02 11 05 91 06 61 08 11 04 91 61 b4 9c 1e 13 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}