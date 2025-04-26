
rule Trojan_BAT_Injector_EARW_MTB{
	meta:
		description = "Trojan:BAT/Injector.EARW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 06 11 04 9a 6f 61 00 00 0a 25 26 a2 11 04 17 58 13 04 09 17 58 0d 11 04 06 8e 69 32 e1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}