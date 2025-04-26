
rule Trojan_BAT_SnakeKeylogger_SPNN_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 91 61 07 11 04 17 58 09 5d 91 59 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}