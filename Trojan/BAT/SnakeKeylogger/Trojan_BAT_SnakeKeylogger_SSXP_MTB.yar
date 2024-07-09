
rule Trojan_BAT_SnakeKeylogger_SSXP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SSXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0c 18 2c 09 11 0c 11 0a 6f ?? ?? ?? 0a 11 0a 6f ?? ?? ?? 0a 13 07 de 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}