
rule Trojan_BAT_BotX_RDQ_MTB{
	meta:
		description = "Trojan:BAT/BotX.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 07 11 06 91 20 fa 00 00 00 61 d2 9c 11 06 17 58 13 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}