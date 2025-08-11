
rule Trojan_BAT_Heracles_BAC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 8e 69 8d 05 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}