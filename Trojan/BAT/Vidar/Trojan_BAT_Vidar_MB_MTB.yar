
rule Trojan_BAT_Vidar_MB_MTB{
	meta:
		description = "Trojan:BAT/Vidar.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a de 03 26 de 00 06 2c 03 16 2b 03 17 2b 00 2d d5 06 2a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}