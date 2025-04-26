
rule Trojan_BAT_Heracles_PSJG_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 03 6f b2 00 00 0a 0a 02 73 b3 00 00 0a 0b 07 06 16 73 b4 00 00 0a 0c 00 02 8e 69 8d 71 00 00 01 0d 08 09 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}