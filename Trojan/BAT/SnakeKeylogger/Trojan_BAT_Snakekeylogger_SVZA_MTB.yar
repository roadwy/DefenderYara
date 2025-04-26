
rule Trojan_BAT_Snakekeylogger_SVZA_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.SVZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0e 05 1f 7b 61 20 ff 00 00 00 5f 0a 06 20 ?? 01 00 00 58 20 00 01 00 00 5e 0a 06 16 fe 01 0b 07 2c 02 17 0a 05 03 04 03 91 0e 04 0e 05 95 61 d2 9c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}