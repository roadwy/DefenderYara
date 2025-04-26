
rule Trojan_BAT_CobaltStrike_AI_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 07 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 07 06 6f ?? 00 00 0a 5d 6f ?? 00 00 0a d2 61 d2 81 ?? 00 00 01 00 11 07 17 58 13 07 11 07 09 8e 69 fe 04 13 09 11 09 2d } //4
		$a_01_1 = {72 00 67 00 5a 00 61 00 49 00 } //1 rgZaI
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}