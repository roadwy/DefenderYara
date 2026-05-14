
rule Trojan_BAT_Bladabindi_BAB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 07 11 04 11 06 11 07 61 61 13 04 2b 0a 11 04 20 f2 6a d4 4d 61 13 04 04 20 84 64 b4 25 61 13 08 11 08 8d 08 00 00 01 13 09 16 13 0a 11 04 13 0b 2b 14 11 09 11 0a 25 17 58 13 0a 07 11 0b 91 9c 11 0b 17 58 13 0b 11 0b 11 04 11 08 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}