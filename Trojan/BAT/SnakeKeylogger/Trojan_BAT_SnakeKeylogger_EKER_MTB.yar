
rule Trojan_BAT_SnakeKeylogger_EKER_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EKER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 31 11 32 91 13 33 03 11 33 ?? ?? ?? ?? ?? 11 32 17 58 13 32 11 32 19 32 e6 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}