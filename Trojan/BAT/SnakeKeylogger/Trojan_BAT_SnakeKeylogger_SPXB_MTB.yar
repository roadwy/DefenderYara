
rule Trojan_BAT_SnakeKeylogger_SPXB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 13 0b 11 0b 08 11 05 17 58 11 04 5d 91 59 20 ?? ?? ?? 00 58 13 0c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}