
rule Trojan_BAT_XWorm_SAN_MTB{
	meta:
		description = "Trojan:BAT/XWorm.SAN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 17 00 00 0a 25 02 6f 18 00 00 0a 25 17 6f 19 00 00 0a 25 17 6f 1a 00 00 0a 28 1b 00 00 0a 26 72 01 00 00 70 28 1c 00 00 0a de 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}