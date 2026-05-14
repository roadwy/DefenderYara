
rule Trojan_BAT_Zusy_SPRO_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SPRO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 14 07 6f ?? ?? ?? 0a 0c 00 06 08 1b 5d 17 58 5a 1f 61 5d 0a 00 07 6f ?? 00 00 0a 2d e4 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}