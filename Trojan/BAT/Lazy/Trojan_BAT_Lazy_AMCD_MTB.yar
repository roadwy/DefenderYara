
rule Trojan_BAT_Lazy_AMCD_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 1b d2 13 2d 11 1b 1e 63 d1 13 1b 11 1a 11 0b 91 13 29 11 1a 11 0b 11 29 11 25 61 19 11 1f 58 61 11 2d 61 d2 9c 11 29 13 1f 11 0b 17 58 13 0b 11 0b 11 28 32 a4 } //2
		$a_01_1 = {11 24 11 12 11 0c 11 12 91 9d 17 11 12 58 13 12 11 12 11 15 32 ea } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}