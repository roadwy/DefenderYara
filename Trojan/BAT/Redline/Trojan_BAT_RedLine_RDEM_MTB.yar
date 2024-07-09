
rule Trojan_BAT_RedLine_RDEM_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 0e 05 04 8e 69 6f ?? ?? ?? ?? 0a 06 0b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}