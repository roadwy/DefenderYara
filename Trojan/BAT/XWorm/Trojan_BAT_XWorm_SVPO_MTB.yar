
rule Trojan_BAT_XWorm_SVPO_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SVPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 28 15 00 00 2b 28 16 00 00 2b 73 88 01 00 0a 0d 11 0d 17 d6 13 0d 11 0d 20 10 27 00 00 31 09 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}