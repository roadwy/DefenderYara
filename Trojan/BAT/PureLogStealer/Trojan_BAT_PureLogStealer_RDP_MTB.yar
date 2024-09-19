
rule Trojan_BAT_PureLogStealer_RDP_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 03 04 6f 29 00 00 0a 0b 02 07 28 39 00 00 06 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}