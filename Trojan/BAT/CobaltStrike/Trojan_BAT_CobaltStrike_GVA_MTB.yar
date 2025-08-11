
rule Trojan_BAT_CobaltStrike_GVA_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 7e 07 00 06 0a 02 2d 0c 03 2d 09 07 28 ef 03 00 06 26 2b 11 07 02 03 28 ee 03 00 06 26 2b 06 20 01 40 00 80 0a 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}