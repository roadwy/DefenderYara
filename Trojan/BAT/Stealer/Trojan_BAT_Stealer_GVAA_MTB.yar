
rule Trojan_BAT_Stealer_GVAA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.GVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 10 00 00 00 fe 0e 02 00 fe 0c 05 00 fe 0c 04 00 fe 0c 18 00 6f ?? 00 00 0a 7e ?? 00 00 04 29 ?? 00 00 11 fe 0c 03 00 fe 0c 18 00 6f ?? 00 00 0a 7e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}