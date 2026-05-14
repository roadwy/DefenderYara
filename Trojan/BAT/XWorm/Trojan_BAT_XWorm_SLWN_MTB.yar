
rule Trojan_BAT_XWorm_SLWN_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SLWN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 37 00 00 04 72 32 01 00 70 28 a8 01 00 06 73 e8 01 00 06 25 28 a9 01 00 06 16 6a 28 aa 01 00 06 25 25 28 a9 01 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}