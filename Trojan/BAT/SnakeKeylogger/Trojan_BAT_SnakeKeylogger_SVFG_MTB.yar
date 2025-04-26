
rule Trojan_BAT_SnakeKeylogger_SVFG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SVFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 20 ff 00 00 00 5f 13 20 11 04 11 20 95 d2 13 21 09 11 1f 07 11 1f 91 11 21 61 d2 9c 00 11 1f 17 58 13 1f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}