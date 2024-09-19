
rule Trojan_BAT_PureLogStealer_RDF_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 09 08 11 04 6f ?? ?? ?? ?? 13 07 11 06 11 07 16 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}