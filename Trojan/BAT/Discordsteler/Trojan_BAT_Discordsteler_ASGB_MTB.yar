
rule Trojan_BAT_Discordsteler_ASGB_MTB{
	meta:
		description = "Trojan:BAT/Discordsteler.ASGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 08 07 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 26 08 20 88 13 00 00 6f 90 01 01 00 00 0a 2c 0a 08 6f 90 01 01 00 00 0a 2d 08 2b 06 08 6f 90 00 } //1
		$a_01_1 = {08 09 07 09 91 06 09 06 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 07 8e 69 32 e7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}