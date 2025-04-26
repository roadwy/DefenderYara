
rule Trojan_BAT_Masslogger_SWA_MTB{
	meta:
		description = "Trojan:BAT/Masslogger.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 11 06 11 0f 11 0f 1b 5a 20 bb 00 00 00 61 d2 9c 00 11 0f 17 58 13 0f 11 0f 11 06 8e 69 fe 04 13 10 11 10 2d da } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}