
rule Trojan_BAT_Heracles_AAH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 08 13 07 16 13 08 2b 20 11 07 11 08 91 13 09 09 72 33 00 00 70 11 09 8c 19 00 00 01 6f ?? ?? ?? 0a 26 11 08 17 58 13 08 11 08 11 07 8e 69 32 d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}