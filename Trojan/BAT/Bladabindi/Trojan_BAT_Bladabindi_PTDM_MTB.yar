
rule Trojan_BAT_Bladabindi_PTDM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PTDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 6f 10 00 00 0a 69 8d 14 00 00 01 0a 08 06 16 06 8e 69 6f 11 00 00 0a 26 de 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}