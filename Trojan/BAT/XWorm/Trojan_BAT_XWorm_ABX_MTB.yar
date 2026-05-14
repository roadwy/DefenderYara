
rule Trojan_BAT_XWorm_ABX_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ABX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 14 17 58 20 00 01 00 00 5d 13 14 11 15 11 0f 11 14 94 58 20 00 01 00 00 5d 13 15 11 0f 11 14 94 13 17 11 0f 11 14 11 0f 11 15 94 9e 11 0f 11 15 11 17 9e 11 0b 11 16 11 0b 11 16 91 11 0f 11 0f 11 14 94 11 0f 11 15 94 58 20 00 01 00 00 5d 94 d2 61 d2 9c 11 16 17 58 13 16 11 16 11 0b 8e 69 32 9d } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}