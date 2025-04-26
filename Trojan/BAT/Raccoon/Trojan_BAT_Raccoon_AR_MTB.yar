
rule Trojan_BAT_Raccoon_AR_MTB{
	meta:
		description = "Trojan:BAT/Raccoon.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 6a 00 28 04 00 00 06 73 1a 00 00 0a 0b 73 15 00 00 0a 0c 07 16 73 1b 00 00 0a 73 1c 00 00 0a 0d 09 08 6f 17 00 00 0a de 0a 09 2c 06 09 6f 1d 00 00 0a dc 08 6f 18 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}