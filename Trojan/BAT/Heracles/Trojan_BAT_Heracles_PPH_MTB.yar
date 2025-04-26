
rule Trojan_BAT_Heracles_PPH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 17 58 20 ff 00 00 00 5f 0c 11 04 06 08 95 58 20 ff 00 00 00 5f 13 04 02 06 08 8f 5c 00 00 01 06 11 04 8f 5c 00 00 01 28 ?? 00 00 06 06 08 95 06 11 04 95 58 20 ff 00 00 00 5f 13 0b 11 06 09 11 05 09 91 06 11 0b 95 61 d2 9c 09 17 58 0d 09 11 05 8e 69 32 aa } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}