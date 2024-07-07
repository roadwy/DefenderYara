
rule Trojan_BAT_Injuke_GND_MTB{
	meta:
		description = "Trojan:BAT/Injuke.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 16 6f 90 01 03 0a 13 08 12 08 28 90 01 03 0a 13 06 11 05 7b 90 01 04 11 06 6f 90 01 03 0a 07 17 58 0b 07 11 04 6f 90 01 03 0a 32 d0 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}