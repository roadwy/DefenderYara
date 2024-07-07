
rule Trojan_BAT_Nanobot_RSD_MTB{
	meta:
		description = "Trojan:BAT/Nanobot.RSD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 cc 00 00 06 1a 2d 22 26 28 53 00 00 0a 06 6f 54 00 00 0a 28 55 00 00 0a 1e 2d 11 } //1
		$a_01_1 = {03 06 91 18 2d 15 26 03 06 03 07 91 9c 03 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}