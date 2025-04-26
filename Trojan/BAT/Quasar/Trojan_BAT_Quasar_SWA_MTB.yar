
rule Trojan_BAT_Quasar_SWA_MTB{
	meta:
		description = "Trojan:BAT/Quasar.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 05 00 00 04 06 8f 03 00 00 02 03 28 10 00 00 06 0d 06 17 62 0a 06 09 58 0a 07 09 08 1f 1f 5f 62 60 0b 08 17 58 0c 08 02 7b 06 00 00 04 32 cf } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}