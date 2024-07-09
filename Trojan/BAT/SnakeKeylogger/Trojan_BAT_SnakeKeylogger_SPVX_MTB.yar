
rule Trojan_BAT_SnakeKeylogger_SPVX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 20 00 01 00 00 58 20 00 01 00 00 5d 13 ?? 07 11 ?? 11 ?? 6a 5d d4 11 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}