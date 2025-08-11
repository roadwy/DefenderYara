
rule Trojan_BAT_Heracles_SHO_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 15 00 00 0a 72 8e 01 00 70 28 16 00 00 0a 6f 17 00 00 0a 28 18 00 00 0a 0b 00 28 15 00 00 0a 72 a8 01 00 70 28 16 00 00 0a 6f 17 00 00 0a 0c 73 23 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}