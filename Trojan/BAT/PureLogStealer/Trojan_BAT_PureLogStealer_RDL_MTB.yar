
rule Trojan_BAT_PureLogStealer_RDL_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 08 11 04 6f 1f 00 00 0a 13 07 11 06 11 07 16 73 20 00 00 0a 13 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}