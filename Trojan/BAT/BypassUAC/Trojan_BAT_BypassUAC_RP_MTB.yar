
rule Trojan_BAT_BypassUAC_RP_MTB{
	meta:
		description = "Trojan:BAT/BypassUAC.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 03 00 20 04 00 00 00 fe 01 39 05 00 00 00 38 05 00 00 00 38 5e ff ff ff 28 20 00 00 06 28 1f 00 00 06 60 28 21 00 00 06 60 28 22 00 00 06 60 28 23 00 00 06 60 39 06 00 00 00 14 28 24 00 00 0a dd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}