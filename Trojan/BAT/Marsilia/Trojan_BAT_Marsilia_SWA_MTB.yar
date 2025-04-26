
rule Trojan_BAT_Marsilia_SWA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 04 00 00 04 06 8f 03 00 00 02 28 1a 00 00 06 06 17 58 0a 06 6e 17 02 7b 05 00 00 04 1f 1f 5f 62 6a 32 db } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}