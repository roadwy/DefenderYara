
rule Trojan_BAT_Redline_PSUQ_MTB{
	meta:
		description = "Trojan:BAT/Redline.PSUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 47 00 00 0a 6f b9 01 00 0a 2c 20 72 93 2c 01 70 16 8d af 00 00 01 28 ba 01 00 0a 73 bb 01 00 0a 7a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}