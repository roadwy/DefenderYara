
rule Trojan_BAT_Remcos_AOS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AOS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 14 00 00 0a 18 2d 03 26 2b 14 0a 2b fb 00 06 28 0f 00 00 06 6f 15 00 00 0a de 03 26 de 00 06 6f 16 00 00 0a 2c e7 28 17 00 00 0a 06 16 6f 18 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}