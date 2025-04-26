
rule Trojan_BAT_PureLogStealer_RDBA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.RDBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 08 11 04 6f 1c 00 00 0a 13 07 11 06 11 07 16 73 1d 00 00 0a 13 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}