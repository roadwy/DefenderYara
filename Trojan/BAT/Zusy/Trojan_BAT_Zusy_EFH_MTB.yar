
rule Trojan_BAT_Zusy_EFH_MTB{
	meta:
		description = "Trojan:BAT/Zusy.EFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 07 00 00 00 02 00 00 00 0b 00 00 00 14 00 00 00 1b 00 00 00 21 00 00 00 2c 00 00 00 3e 00 00 00 2b 4f 73 03 00 00 0a 0b 17 2b d4 7e 01 00 00 0a 0c 18 2b cb 02 17 da 0d 19 2b c4 16 13 04 1a 2b be } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}