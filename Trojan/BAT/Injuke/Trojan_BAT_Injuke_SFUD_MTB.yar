
rule Trojan_BAT_Injuke_SFUD_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SFUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 32 16 2d e4 2b 34 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0b de 38 06 2b cf 28 ?? 00 00 0a 2b cf 6f ?? 00 00 0a 2b ca 06 2b cc 28 ?? 00 00 0a 2b cc 6f ?? 00 00 0a 2b c7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}