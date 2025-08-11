
rule Trojan_BAT_RedLine_ACG_MTB{
	meta:
		description = "Trojan:BAT/RedLine.ACG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f ?? 00 00 0a 13 06 04 03 6f ?? 00 00 0a 59 13 07 11 07 19 fe 04 16 fe 01 } //3
		$a_03_1 = {07 11 04 5a 08 58 13 08 06 11 08 17 6f ?? 00 00 0a 00 1a 13 05 2b 1b 08 17 58 0c 18 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}