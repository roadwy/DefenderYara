
rule Trojan_BAT_SnakeKeylogger_EHFM_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EHFM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0c 91 11 0c 1e 5a 1f 1f 5f 62 58 0a 00 11 0c 17 58 13 0c 11 0c 03 ?? ?? ?? ?? ?? 8e 69 1a ?? ?? ?? ?? ?? fe 04 13 0d 11 0d 2d cc } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}