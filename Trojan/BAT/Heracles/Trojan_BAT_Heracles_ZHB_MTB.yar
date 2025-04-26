
rule Trojan_BAT_Heracles_ZHB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ZHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 07 16 8f ?? 00 00 01 13 0a 11 0a e0 13 09 00 16 13 0b 2b 24 00 11 09 11 0b 58 06 11 0b 58 47 08 11 0b 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 52 00 11 0b 17 58 13 0b 11 0b 07 8e 69 fe 04 13 0c 11 0c 2d cf } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}