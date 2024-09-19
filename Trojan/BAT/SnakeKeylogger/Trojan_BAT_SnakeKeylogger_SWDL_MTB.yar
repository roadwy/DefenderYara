
rule Trojan_BAT_SnakeKeylogger_SWDL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SWDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {19 2c 0d 2b 0d 72 01 00 00 70 2b 0d 2b 12 2b 17 de 1b 73 8c 00 00 0a 2b ec 28 ?? ?? ?? 0a 2b ec 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}