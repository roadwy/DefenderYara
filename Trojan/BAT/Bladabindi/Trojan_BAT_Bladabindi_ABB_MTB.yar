
rule Trojan_BAT_Bladabindi_ABB_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ABB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 00 00 07 08 16 20 00 10 00 00 6f ?? 00 00 0a 13 04 11 04 16 fe 02 13 05 11 05 2c 0b 09 08 16 11 04 6f ?? 00 00 0a 00 00 11 04 16 fe 02 13 05 11 05 2d cf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}