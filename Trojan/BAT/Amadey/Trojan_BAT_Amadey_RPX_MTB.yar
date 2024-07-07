
rule Trojan_BAT_Amadey_RPX_MTB{
	meta:
		description = "Trojan:BAT/Amadey.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 78 00 00 04 09 91 13 04 11 04 16 31 2b 02 7b 7b 00 00 04 09 06 11 04 17 59 94 28 5f 00 00 06 9d 06 11 04 17 59 8f 50 00 00 01 25 4a 17 1f 10 11 04 59 1f 1f 5f 62 58 54 09 17 58 0d 09 02 7b 7a 00 00 04 32 b9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}