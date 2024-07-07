
rule Trojan_BAT_Snakekeylogger_PSXW_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.PSXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 3b 00 00 0a 28 90 01 01 00 00 2b 0b 72 1a 03 00 70 28 90 01 01 00 00 06 02 7b 09 00 00 04 02 07 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 0c 08 28 90 01 01 00 00 0a 72 e0 01 00 70 28 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}