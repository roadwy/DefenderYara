
rule Trojan_BAT_Vidar_PTHK_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PTHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 00 20 e8 03 00 00 28 7a 00 00 0a 00 00 de 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}