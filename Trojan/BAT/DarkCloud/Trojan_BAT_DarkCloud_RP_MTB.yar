
rule Trojan_BAT_DarkCloud_RP_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {26 16 00 20 00 00 00 00 28 35 00 00 06 28 13 00 00 0a 0a 20 04 00 00 00 28 35 00 00 06 28 13 00 00 0a 0b 06 07 28 03 00 00 06 00 2a } //1
		$a_01_1 = {26 16 73 06 00 00 06 0a 06 28 14 00 00 0a 7d 02 00 00 04 06 02 7d 03 00 00 04 06 15 7d 01 00 00 04 06 7c 02 00 00 04 12 00 28 01 00 00 2b 06 7c 02 00 00 04 28 16 00 00 0a 2a } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10) >=11
 
}