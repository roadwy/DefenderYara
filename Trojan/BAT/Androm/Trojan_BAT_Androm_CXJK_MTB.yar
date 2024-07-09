
rule Trojan_BAT_Androm_CXJK_MTB{
	meta:
		description = "Trojan:BAT/Androm.CXJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 13 08 16 13 09 11 08 12 09 28 ?? ?? ?? ?? 00 08 07 11 07 18 6f 17 00 00 0a 1f 10 28 18 00 00 0a 6f 19 00 00 0a 00 de 0d 11 09 2c 08 11 08 28 1a 00 00 0a 00 dc 00 11 07 18 58 13 07 11 07 07 6f 1b 00 00 0a fe 04 13 0a 11 0a 2d b2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}