
rule Trojan_BAT_Spynoon_PIAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.PIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 0b 2b 0a 06 07 02 07 91 9d 07 17 58 0b 07 02 8e 69 32 f0 } //2
		$a_03_1 = {0a 7e 25 00 00 04 7e 26 00 00 04 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 2a } //2
		$a_01_2 = {48 00 65 00 79 00 43 00 61 00 6e 00 49 00 50 00 6f 00 70 00 53 00 68 00 69 00 74 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 HeyCanIPopShit.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}