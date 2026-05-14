
rule Trojan_BAT_XWorm_SLWW_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SLWW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {10 00 28 9c 00 00 0a 0a 03 20 4b 01 00 00 59 10 01 06 72 7f 00 00 70 6f 9d 00 00 0a 0b 02 03 61 0c 08 1f 11 5a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}