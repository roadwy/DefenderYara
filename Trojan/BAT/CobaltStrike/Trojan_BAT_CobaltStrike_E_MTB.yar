
rule Trojan_BAT_CobaltStrike_E_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 06 06 1f 10 28 ?? 00 00 06 6f ?? 00 00 0a 0c 73 } //2
		$a_03_1 = {09 08 17 73 ?? 00 00 0a 13 04 11 04 07 16 07 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 de } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}