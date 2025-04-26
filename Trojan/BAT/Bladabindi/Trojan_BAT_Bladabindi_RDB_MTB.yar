
rule Trojan_BAT_Bladabindi_RDB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 04 17 28 9a 00 00 0a 13 0b 08 11 07 06 11 0b 28 9b 00 00 0a 11 09 61 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}