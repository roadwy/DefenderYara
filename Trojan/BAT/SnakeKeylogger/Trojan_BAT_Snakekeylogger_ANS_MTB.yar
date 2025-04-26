
rule Trojan_BAT_Snakekeylogger_ANS_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.ANS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2b 14 07 06 07 8e 69 5d 02 06 08 07 28 ?? ?? ?? 06 9c 06 15 58 0a 06 16 fe 04 16 fe 01 13 05 11 05 2d df } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}