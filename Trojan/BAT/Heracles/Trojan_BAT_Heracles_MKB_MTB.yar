
rule Trojan_BAT_Heracles_MKB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 05 00 00 0a 72 01 00 00 70 0b 25 6f 06 00 00 0a 26 07 6f 07 00 00 0a 73 08 00 00 0a 0c 08 6f 09 00 00 0a 0d 06 09 6f 0a 00 00 0a 26 de 0a } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}