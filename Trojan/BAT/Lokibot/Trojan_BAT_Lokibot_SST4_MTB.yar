
rule Trojan_BAT_Lokibot_SST4_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.SST4!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {87 5a 20 da c6 74 89 61 2b 90 01 01 07 6f 90 01 03 0a 0a 11 90 01 01 20 90 01 03 43 5a 20 90 01 03 76 61 2b 90 01 01 07 02 09 18 6f 90 01 03 0a 1f 90 01 01 28 90 01 03 0a 84 28 90 01 03 0a 6f 90 01 03 0a 26 20 90 01 03 9f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}