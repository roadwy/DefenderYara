
rule Trojan_BAT_Heracles_ZKQ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ZKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {7a 11 0a 16 28 ?? 00 00 0a 13 03 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 02 00 00 00 38 ?? ff ff ff 00 20 00 10 00 00 8d ?? 00 00 01 13 05 } //6
		$a_03_1 = {11 01 11 05 16 11 06 6f ?? 00 00 0a 38 ?? 00 00 00 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 25 13 06 16 3d d8 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}