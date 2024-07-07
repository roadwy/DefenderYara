
rule Trojan_BAT_LokiBot_RDS_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6e 11 4e 20 ff 00 00 00 5f 6a 61 d2 9c 00 11 4a 17 6a 58 13 4a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}