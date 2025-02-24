
rule Trojan_BAT_Ursu_SWA_MTB{
	meta:
		description = "Trojan:BAT/Ursu.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 28 02 00 00 0a 0a 08 06 16 06 8e b7 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 00 28 ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 10 00 de 0d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}