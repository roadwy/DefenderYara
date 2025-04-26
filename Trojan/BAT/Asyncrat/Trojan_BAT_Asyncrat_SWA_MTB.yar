
rule Trojan_BAT_Asyncrat_SWA_MTB{
	meta:
		description = "Trojan:BAT/Asyncrat.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 0e 00 00 04 2d 1c 28 ?? 00 00 06 14 fe 06 27 00 00 06 73 6d 00 00 0a 6f ?? 00 00 0a 17 80 0e 00 00 04 de 07 07 28 ?? 00 00 0a dc 7e 0d 00 00 04 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}