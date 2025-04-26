
rule Trojan_BAT_SnakeKeylogger_MBYX_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MBYX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 91 11 ?? 61 06 17 58 11 ?? 5d 13 ?? 07 11 ?? 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}