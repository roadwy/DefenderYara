
rule Trojan_BAT_Heracles_BAD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 04 00 00 01 0a 03 8e 69 0b 16 0c 2b 11 06 08 02 08 91 03 08 07 5d 91 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e9 06 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}