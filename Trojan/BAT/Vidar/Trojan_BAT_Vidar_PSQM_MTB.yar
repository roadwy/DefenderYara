
rule Trojan_BAT_Vidar_PSQM_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PSQM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 17 28 27 00 00 0a 00 00 28 12 00 00 06 6f 28 00 00 0a 26 28 11 00 00 06 6f 28 00 00 0a 26 00 de 30 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}