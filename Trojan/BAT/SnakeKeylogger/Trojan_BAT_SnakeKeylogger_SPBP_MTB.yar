
rule Trojan_BAT_SnakeKeylogger_SPBP_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 28 ?? ?? ?? 0a 07 11 ?? 17 58 07 8e 69 5d 91 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}