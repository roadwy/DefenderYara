
rule Trojan_BAT_SnakeKeylogger_SPVF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 91 11 ?? 61 09 17 58 07 8e 69 5d 13 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}