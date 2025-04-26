
rule Trojan_BAT_XWorm_SIG_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 06 07 28 14 00 00 0a 0c 08 72 51 89 01 70 72 5b 89 01 70 6f 15 00 00 0a 28 16 00 00 0a 0d 14 13 04 11 04 13 05 09 28 17 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}