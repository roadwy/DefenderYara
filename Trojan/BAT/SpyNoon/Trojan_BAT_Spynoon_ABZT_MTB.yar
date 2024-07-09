
rule Trojan_BAT_Spynoon_ABZT_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.ABZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 08 11 07 6f ?? 00 00 0a 13 09 16 13 0a 11 06 13 0c 11 0c 13 0b 11 0b } //2
		$a_03_1 = {2b 21 12 09 28 ?? 00 00 0a 13 0a 2b 16 12 09 28 ?? 00 00 0a 13 0a 2b 0b 12 09 28 ?? 00 00 0a 13 0a 2b 00 07 11 0a 6f ?? 00 00 0a 00 00 11 08 17 58 13 08 11 08 09 fe 04 13 0d 11 0d 2d 97 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}