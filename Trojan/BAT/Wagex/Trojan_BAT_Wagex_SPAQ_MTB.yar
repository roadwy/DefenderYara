
rule Trojan_BAT_Wagex_SPAQ_MTB{
	meta:
		description = "Trojan:BAT/Wagex.SPAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 13 05 2b 0d 00 08 07 11 05 91 6f ?? ?? ?? 0a 00 00 11 05 25 17 59 13 05 16 fe 02 13 06 11 06 2d e3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}