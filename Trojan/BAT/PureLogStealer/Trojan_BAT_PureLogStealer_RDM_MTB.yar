
rule Trojan_BAT_PureLogStealer_RDM_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 11 00 00 0a 6f 12 00 00 0a 0b 73 0e 00 00 0a 0c 08 07 17 73 13 00 00 0a 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}