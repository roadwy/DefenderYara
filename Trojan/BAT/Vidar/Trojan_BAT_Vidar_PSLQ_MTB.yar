
rule Trojan_BAT_Vidar_PSLQ_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PSLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 05 00 00 06 28 07 00 00 06 74 04 00 00 01 28 06 00 00 06 74 01 00 00 1b 28 03 00 00 06 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}