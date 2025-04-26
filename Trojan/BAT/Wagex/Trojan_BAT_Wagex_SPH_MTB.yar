
rule Trojan_BAT_Wagex_SPH_MTB{
	meta:
		description = "Trojan:BAT/Wagex.SPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 17 73 2c 00 00 0a 0d 07 02 20 ?? ?? ?? 00 06 09 6f ?? ?? ?? 0a 26 08 17 58 0c 08 1f 32 fe 02 16 fe 01 13 04 11 04 2d d7 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}