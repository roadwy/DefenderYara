
rule Trojan_BAT_Alien_MK_MTB{
	meta:
		description = "Trojan:BAT/Alien.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 03 00 00 01 0b 07 6f 03 00 00 0a 73 04 00 00 0a 6f 05 00 00 0a 0c 28 06 00 00 0a 0d 09 08 6f 07 00 00 0a 26 09 6f 08 00 00 0a } //35
		$a_81_1 = {68 74 74 70 3a 2f 2f } //5 http://
		$a_81_2 = {68 74 74 70 73 3a 2f 2f } //5 https://
	condition:
		((#a_01_0  & 1)*35+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5) >=40
 
}