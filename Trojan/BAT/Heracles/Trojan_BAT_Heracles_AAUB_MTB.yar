
rule Trojan_BAT_Heracles_AAUB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AAUB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 09 28 ?? 00 00 06 20 02 00 00 00 38 ?? ff ff ff 00 00 11 05 6f ?? 00 00 0a 13 0c 38 ?? 00 00 00 00 11 05 17 28 ?? 00 00 06 20 00 00 00 00 28 ?? 00 00 06 39 } //2
		$a_03_1 = {11 0c 11 0b 16 11 0b 8e 69 28 ?? 00 00 06 13 07 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}