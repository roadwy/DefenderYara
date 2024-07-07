
rule Trojan_BAT_Mardom_AMA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 2b f8 02 50 06 91 1d 2d 18 26 02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}